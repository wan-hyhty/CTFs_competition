package ue

import (
	"bytes"
	"errors"
	"net"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/pkg/nas"
	"phreaking/pkg/parser"
)

var (
	errDecode = errors.New("cannot decode message")
)

func (u *UE) HandlePDURes(c net.Conn, msgbuf []byte) error {
	var msg nas.PDUResMsg

	err := parser.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errDecode
	}

	u.Logger.Sugar().Debugf("http response len: %d", len(msg.Response))
	return nil
}

func (u *UE) HandlePDUSessionEstAccept(c net.Conn, msgbuf []byte) error {
	var msg nas.PDUSessionEstAcceptMsg

	err := parser.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errDecode
	}

	u.ActivePduId = msg.PduSesId

	pduReq := nas.PDUReqMsg{PduSesId: u.ActivePduId, Request: []byte("gopher://gopher.website.org/")}

	pduReqMsg, mac, err := nas.BuildMessage(u.EaAlg, u.IaAlg, &pduReq)
	if err != nil {
		return err
	}

	gmm := nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUReq, Message: pduReqMsg}
	return io.SendGmm(c, gmm)
}

func (u *UE) HandleNASSecurityModeCommand(c net.Conn, msgbuf []byte) error {
	var msg nas.NASSecurityModeCommandMsg
	err := parser.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode")
	}

	u.EaAlg = msg.EaAlg
	u.IaAlg = msg.IaAlg

	location, err := u.GetLocation()
	if err != nil {
		return err
	}
	loc := nas.LocationUpdateMsg{Location: location}
	locMsg, mac, err := nas.BuildMessage(u.EaAlg, u.IaAlg, &loc)
	if err != nil {
		return err
	}

	gmm := nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.LocationUpdate, Message: locMsg}
	err = io.SendGmm(c, gmm)
	if err != nil {
		return err
	}

	pduEstReq := nas.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 0}
	pduEstReqMsg, mac, err := nas.BuildMessage(u.EaAlg, u.IaAlg, &pduEstReq)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUSessionEstRequest, Message: pduEstReqMsg}
	return io.SendGmm(c, gmm)
}

func (u *UE) HandleNASAuthRequest(c net.Conn, msgbuf []byte) error {
	var msg nas.NASAuthRequestMsg
	err := parser.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode")
	}

	if !(bytes.Equal(crypto.IA2(msg.AuthRand), msg.Auth)) {
		return errors.New("cannot authenticate core")
	}

	res := crypto.IA2(msg.Rand)
	authRes := nas.NASAuthResponseMsg{Res: res}
	authResMsg, mac, err := nas.BuildMessagePlain(&authRes)
	if err != nil {
		return err
	}

	gmm := nas.GmmHeader{Security: false, Mac: mac, MessageType: nas.NASAuthResponse, Message: authResMsg}
	return io.SendGmm(c, gmm)
}
