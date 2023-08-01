package main

import (
	"net"
	"phreaking/internal/core"

	"go.uber.org/zap"
)

func main() {
	logger := zap.Must(zap.NewDevelopment())
	defer logger.Sync()
	log := logger.Sugar()

	l, err := net.Listen("tcp4", ":3399")
	if err != nil {
		log.Fatalf("tcp server failed to listen: %v", err)
		return
	}
	defer l.Close()

	// 0x00ff10 = MCC 001, MNC 01
	amf := core.Amf{Logger: logger, AmfName: "CORE", GuamPlmn: 0x00ff10, AmfRegionId: 1, AmfSetId: 1, AmfPtr: 0, AmfCap: 255}

	for {
		c, err := l.Accept()
		if err != nil {
			log.Warnf("connection for listener failed: %v", err)
			return
		}
		go amf.HandleConnection(c)
	}
}
