package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/pkg/nas"
	"phreaking/pkg/ngap"
	"phreaking/pkg/parser"
	"time"

	"github.com/gofrs/uuid"
)

var (
	errDecode  = errors.New("cannot decode message")
	errEncode  = errors.New("cannot encode message")
	errAuth    = errors.New("cannot authenticate UE")
	errNotAuth = errors.New("not authenticated")
)

func (amf *Amf) HandleConnection(c net.Conn) {
	log := amf.Logger.Sugar()
	log.Infof("Serving %s", c.RemoteAddr().String())

	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
		log.Infof("Closed connection for remote: %s", c.RemoteAddr().String())
	}()

	var amfg *AmfGNB

	for {
		select {
		case <-timeout.C:
			log.Infof("HandleConnection timeout for remote: %s", c.RemoteAddr().String())
			return
		default:
			buf, err := io.Recv(c)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Warnf("EOF: %s", c.RemoteAddr().String())
				}
				return
			}

			var ngapHeader ngap.NgapHeader
			err = parser.DecodeMsg(buf, &ngapHeader)
			if err != nil {
				log.Warnf("Cannot decode Gmm Header")
				return
			}

			msgType := ngapHeader.MessageType
			msgbuf := ngapHeader.NgapPdu

			if msgType == ngap.NGSetupRequest && amfg == nil {
				amfg, err = amf.handleNGSetupRequest(c, msgbuf)
				if err != nil {
					log.Errorf("Error creating gNB %w", err)
					return
				}
			} else if amfg != nil {
				err = amf.HandleTransport(c, ngapHeader, amfg)
				if err != nil {
					log.Errorf("Error NGAP: %w", err)
					return
				}
			} else {
				log.Errorln("Error gNB connection")
				return
			}
		}
	}
}

func (amf *Amf) handleNGSetupRequest(c net.Conn, buf []byte) (*AmfGNB, error) {
	var msg ngap.NGSetupRequestMsg
	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return nil, errDecode
	}

	amfg := &AmfGNB{GranId: msg.GranId, Tac: msg.Tac, Plmn: msg.Plmn, AmfUEs: make(map[ngap.AmfUeNgapIdType]AmfUE)}

	// 0x00ff10 = MCC 001, MNC 01
	resMsg := ngap.NGSetupResponseMsg{AmfName: amf.AmfName, GuamPlmn: 0x00ff10,
		AmfRegionId: amf.AmfRegionId, AmfSetId: amf.AmfSetId, AmfPtr: amf.AmfPtr,
		AmfCap: amf.AmfCap, Plmn: msg.Plmn}

	return amfg, io.SendNgapMsg(c, ngap.NGSetupResponse, &resMsg)
}

func (amf *Amf) HandleTransport(c net.Conn, ngapHeader ngap.NgapHeader, amfg *AmfGNB) error {
	msgType := ngapHeader.MessageType

	switch msgType {
	case ngap.InitUEMessage:
		err := amf.handleInitUEMessage(c, ngapHeader.NgapPdu, amfg)
		if err != nil {
			return err
		}
	case ngap.UpNASTrans:
		err := amf.handleUpNASTrans(c, ngapHeader.NgapPdu, amfg)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid message type (%d) for NGAP (non NAS-PDU)", msgType)
	}
	return nil
}

func (amf *Amf) handleUpNASTrans(c net.Conn, buf []byte, amfg *AmfGNB) error {
	var msg ngap.UpNASTransMsg
	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	msgbuf := msg.NasPdu.Message
	ue, ok := amfg.AmfUEs[msg.AmfUeNgapId]
	if ok {
		if msg.NasPdu.Security {
			err = crypto.CheckIntegrity(ue.IaAlg, msgbuf, msg.NasPdu.Mac)
			if err != nil {
				return err
			}

			msgbuf, err = crypto.Decrypt(ue.EaAlg, msg.NasPdu.Message)
			if err != nil {
				return err
			}
		}

		err = amf.handleNASPDU(c, msg.NasPdu.MessageType, msgbuf, amfg, &ue)
		if err != nil {
			return err
		}
		// Update UE state
		amfg.AmfUEs[msg.AmfUeNgapId] = ue
		return nil
	}
	return errors.New("cannot find NG for AmfUeNgapId")
}

func (amf *Amf) handleNASPDU(c net.Conn, msgType nas.NasMsgType, msgBuf []byte, amfg *AmfGNB, ue *AmfUE) error {
	switch msgType {
	case nas.NASAuthResponse:
		err := amf.handleNASAuthResponse(c, msgBuf, amfg, ue)
		if err != nil {
			return err
		}
	case nas.PDUSessionEstRequest:
		err := amf.handlePDUSessionEstRequest(c, msgBuf, amfg, ue)
		if err != nil {
			return err
		}
	case nas.LocationUpdate:
		err := amf.handleLocationUpdate(c, msgBuf, amfg, ue)
		if err != nil {
			return err
		}
	case nas.PDUReq:
		err := amf.handlePDUReq(c, msgBuf, amfg, ue)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid message type for NAS-PDU")
	}
	return nil
}

func (amf *Amf) handlePDUReq(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg nas.PDUReqMsg

	if !ue.Authenticated {
		return errNotAuth
	}

	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	pduType, ok := ue.PDUs[msg.PduSesId]
	if !ok {
		return errors.New("pdu session id not found")
	}

	switch pduType {
	case 0:
		/*
			res, err := http.Get(string(msg.Request))
			if err != nil {
				return err
			}

			response, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return err
			}
		*/
		response := ` 
		<!DOCTYPE html>
			<html>
			<head>
			</head>
			<body>
				<h1>Web page</h1>

				<div>
					<p>
						HELLO FROM A UNIX SYSTEM	
					</p>
				</div>
			</body>
			</html>
		`
		pduRes := nas.PDUResMsg{PduSesId: msg.PduSesId, Response: []byte(response)}
		pduResMsg, mac, err := nas.BuildMessage(ue.EaAlg, ue.IaAlg, &pduRes)
		if err != nil {
			return errDecode
		}

		gmm := nas.GmmHeader{true, mac, nas.PDUSessionEstAccept, pduResMsg}
		downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: gmm}
		return io.SendNgapMsg(c, ngap.DownNASTrans, &downTrans)
	default:
		return errors.New("pdu type not supported")
	}
}

func (amf *Amf) handleLocationUpdate(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg nas.LocationUpdateMsg

	if !ue.Authenticated {
		return errNotAuth
	}

	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	ue.Locations = append(ue.Locations, msg.Location)
	return nil
}

func (amf *Amf) handlePDUSessionEstRequest(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg nas.PDUSessionEstRequestMsg

	if !ue.Authenticated {
		return errNotAuth
	}

	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	ue.PDUs[msg.PduSesId] = msg.PduSesType

	pduAcc := nas.PDUSessionEstAcceptMsg{PduSesId: msg.PduSesId}
	pduAccMsg, mac, err := nas.BuildMessage(ue.EaAlg, ue.IaAlg, &pduAcc)
	if err != nil {
		return errDecode
	}

	gmm := nas.GmmHeader{true, mac, nas.PDUSessionEstAccept, pduAccMsg}
	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: gmm}
	return io.SendNgapMsg(c, ngap.DownNASTrans, &downTrans)
}

func handlePDUSessionResourceSetupRequest() {
	panic("unimplemented")
}

func handleRegisterComplete() {
	panic("unimplemented")
}

func handleInitialContextSetupResponse() {
	panic("unimplemented")
}

func handleUECapInfoIndication() {
	panic("unimplemented")
}

func handleNASSecurityModeComplete() {
	panic("unimplemented")
}

func handleNASIdResponse() {
	panic("unimplemented")
}

func (amf *Amf) handleInitUEMessage(c net.Conn, buf []byte, amfg *AmfGNB) error {
	var initmsg ngap.InitUEMessageMsg
	err := parser.DecodeMsg(buf, &initmsg)
	if err != nil {
		return errDecode
	}

	ue := AmfUE{RanUeNgapId: initmsg.RanUeNgapId, PDUs: make(map[uint8]uint8)}

	msgType := initmsg.NasPdu.MessageType
	if msgType != nas.NASRegRequest {
		return errors.New("InitUEMessage contains unknown message type")
	}
	var regmsg nas.NASRegRequestMsg
	err = parser.DecodeMsg(initmsg.NasPdu.Message, &regmsg)
	if err != nil {
		return errDecode
	}

	ue.SecCap = regmsg.SecCap

	randToken := make([]byte, 32)
	rand.Read(randToken)

	authRand := make([]byte, 32)
	rand.Read(authRand)

	auth := crypto.IA2(authRand)

	ue.RandToken = randToken

	authReq := nas.NASAuthRequestMsg{Rand: ue.RandToken, AuthRand: authRand, Auth: auth}

	authReqbuf, mac, err := nas.BuildMessagePlain(&authReq)
	if err != nil {
		return errEncode
	}

	gmm := nas.GmmHeader{false, mac, nas.NASAuthRequest, authReqbuf}

	uv4, _ := uuid.NewV4()
	amfueid := ngap.AmfUeNgapIdType(uv4)
	ue.AmfUeNgapId = amfueid

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: gmm}

	amfg.AmfUEs[amfueid] = ue
	return io.SendNgapMsg(c, ngap.DownNASTrans, &downTrans)
}

func (amf *Amf) handleNASAuthResponse(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg nas.NASAuthResponseMsg
	err := parser.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	hkres := crypto.ComputeHash(crypto.IA2(ue.RandToken))
	hres := crypto.ComputeHash(msg.Res)

	if hkres != hres {
		return errAuth
	}

	amf.Logger.Sugar().Infoln("AUTHENTICATION SUCCESSFULL")
	ue.Authenticated = true

	var EA uint8
	var IA uint8

	for i := len(nas.EaMaskMap) - 1; i >= 0; i-- {
		alg := nas.EaMaskMap[i]
		if ue.SecCap.EaCap&alg != 0 {
			EA = uint8(i)
			break
		}
	}

	for i := len(nas.IaMaskMap) - 1; i >= 0; i-- {
		alg := nas.IaMaskMap[i]
		if ue.SecCap.IaCap&alg != 0 {
			IA = uint8(i)
			break
		}
	}

	ue.EaAlg = EA
	ue.IaAlg = IA
	secModeCmd := nas.NASSecurityModeCommandMsg{EaAlg: ue.EaAlg,
		IaAlg: ue.IaAlg, ReplaySecCap: ue.SecCap,
	}
	secModeMsg, mac, err := nas.BuildMessagePlain(&secModeCmd)
	if err != nil {
		return errDecode
	}

	gmm := nas.GmmHeader{false, mac, nas.NASSecurityModeCommand, secModeMsg}
	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: gmm}
	return io.SendNgapMsg(c, ngap.DownNASTrans, &downTrans)
}
