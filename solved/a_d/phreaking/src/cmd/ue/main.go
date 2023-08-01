package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/internal/ue"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/nas"
	"phreaking/pkg/parser"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func handleConnection(logger *zap.Logger, c net.Conn) {
	log := logger.Sugar()
	log.Infof("Serving %s", c.RemoteAddr().String())

	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
		log.Infof("Closed connection for remote: %s", c.RemoteAddr().String())
	}()

	u := *ue.NewUE(logger)

	err := sendRegistrationRequest(&u, c)
	if err != nil {
		log.Error(err)
		return
	}

	u.ToState(ue.RegistrationInitiated)

	for {
		select {
		case <-timeout.C:
			log.Infof("handleConnection timeout for remote: %s", c.RemoteAddr().String())
			return
		default:
			buf, err := io.Recv(c)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Warnf("EOF: %s", c.RemoteAddr().String())
				}
				return
			}

			var gmm nas.GmmHeader
			err = parser.DecodeMsg(buf, &gmm)
			if err != nil {
				log.Warnf("Cannot decode Gmm Header")
				return
			}

			msgbuf := gmm.Message

			if gmm.Security {
				err = crypto.CheckIntegrity(u.IaAlg, msgbuf, gmm.Mac)
				if err != nil {
					log.Error(err)
					return
				}

				msgbuf, err = crypto.Decrypt(u.EaAlg, msgbuf)
				if err != nil {
					log.Error(err)
					return
				}
			}

			msgType := gmm.MessageType

			switch {
			case msgType == nas.NASAuthRequest && u.InState(ue.RegistrationInitiated):
				err := u.HandleNASAuthRequest(c, msgbuf)
				if err != nil {
					log.Errorf("Error NASAuthRequest: %w", err)
					return
				}
				u.ToState(ue.Authentication)
			case msgType == nas.NASSecurityModeCommand && u.InState(ue.Authentication):
				err := u.HandleNASSecurityModeCommand(c, msgbuf)
				if err != nil {
					log.Errorf("Error NASSecurityModeCommand: %w", err)
					return
				}
				u.ToState(ue.SecurityMode)
			case msgType == nas.PDUSessionEstAccept && u.InState(ue.SecurityMode):
				err := u.HandlePDUSessionEstAccept(c, msgbuf)
				if err != nil {
					log.Errorf("Error PDUSessionEstAccept: %w", err)
					return
				}
				u.ToState(ue.Registered)
			case msgType == nas.PDURes && u.InState(ue.Registered):
				err := u.HandlePDURes(c, msgbuf)
				if err != nil {
					log.Errorf("Error PDURes: %w", err)
					return
				}
			default:
				log.Warnf("invalid message type (%d) for UE ", msgType)
				return
			}
		}
	}

}

func sendRegistrationRequest(u *ue.UE, c net.Conn) error {
	sec := nas.SecCapType{EaCap: nas.EA1, IaCap: nas.IA1 ^ nas.IA2 ^ nas.IA3 ^ nas.IA4}
	regMsg := nas.NASRegRequestMsg{
		MobileId: nas.MobileIdType{Mcc: 1, Mnc: 1, HomeNetPki: 0, Msin: 0},
		SecCap:   sec,
	}
	u.SecCap = sec

	msg, err := parser.EncodeMsg(&regMsg)
	if err != nil {
		return err
	}

	gmm := nas.GmmHeader{Security: false, Mac: [8]byte{}, MessageType: nas.NASRegRequest, Message: msg}
	return io.SendGmm(c, gmm)
}

func main() {
	logger := zap.Must(zap.NewDevelopment())
	defer logger.Sync()
	log := logger.Sugar()

	readFile, err := os.Create("/service/data/location.data")
	if err != nil {
		log.Fatalf("Could not create location file")
	}
	readFile.Close()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 9930))
	if err != nil {
		log.Fatalf("grpc server failed to listen: %v", err)
	}
	defer lis.Close()

	s := pb.Server{}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(pb.AuthInterceptor))

	pb.RegisterLocationServer(grpcServer, &s)
	reflection.Register(grpcServer)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("grpc failed to serve: %s", err)
		}
	}()

	l, err := net.Listen("tcp4", ":6060")
	if err != nil {
		log.Fatalf("tcp server failed to listen: %v", err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Warnf("connection for listener failed: %v", err)
			return
		}
		go handleConnection(logger, c)
	}
}
