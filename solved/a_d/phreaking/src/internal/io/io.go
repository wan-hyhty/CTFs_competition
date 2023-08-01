package io

import (
	"errors"
	"io"
	"net"
	"phreaking/pkg/nas"
	"phreaking/pkg/ngap"
	"phreaking/pkg/parser"
)

var EOF error = io.EOF

func Send(conn net.Conn, msg []byte) (err error) {
	msgLen := uint16(len(msg))
	buf := make([]byte, 2)
	buf[0] = uint8(msgLen >> 8)
	buf[1] = uint8(msgLen & 0xff)
	_, err = conn.Write(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	if err != nil {
		return err
	}
	return nil
}

func SendGmm(conn net.Conn, gmm nas.GmmHeader) (err error) {
	pkt, err := parser.EncodeMsg(&gmm)
	if err != nil {
		return err
	}

	return Send(conn, pkt)
}

func SendNgapMsg[T any](conn net.Conn, ngapType ngap.NgapMsgType, msgPtr *T) (err error) {
	ngapPdu, err := parser.EncodeMsg(&msgPtr)
	if err != nil {
		return err
	}
	ngapHeader := ngap.NgapHeader{MessageType: ngapType, NgapPdu: ngapPdu}
	pkt, err := parser.EncodeMsg(&ngapHeader)
	if err != nil {
		return err
	}

	return Send(conn, pkt)
}

func Recv(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	msgLen := uint16(buf[1]) | uint16(buf[0])<<8
	if msgLen < 1 {
		return nil, errors.New("msg length of buffer is zero or negative")
	}
	buf = make([]byte, msgLen)
	_, err = conn.Read(buf)
	return buf, err

}
