package ngap

import (
	"phreaking/pkg/nas"

	"github.com/gofrs/uuid"
)

type NgapMsgType int
type AmfUeNgapIdType uuid.UUID

const (
	// Interface Management Messages
	NGSetupRequest NgapMsgType = iota
	NGSetupResponse
	NGSetupFailure
	// NAS Transport
	InitUEMessage
	DownNASTrans
	UpNASTrans
)

type NgapHeader struct {
	MessageType NgapMsgType
	NgapPdu     []byte
}

type NGSetupRequestMsg struct {
	GranId uint32
	Tac    uint32
	Plmn   uint32
}

type NGSetupResponseMsg struct {
	AmfName     string
	GuamPlmn    uint32
	AmfRegionId uint16
	AmfSetId    uint32
	AmfPtr      uint32
	AmfCap      uint8
	Plmn        uint32
}

type InitUEMessageMsg struct {
	RanUeNgapId uint32
	NasPdu      nas.GmmHeader
	// Location
}

type DownNASTransMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
	NasPdu      nas.GmmHeader
}

type UpNASTransMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
	NasPdu      nas.GmmHeader
	// Location
}
