package core

import (
	"phreaking/pkg/nas"
	"phreaking/pkg/ngap"

	"go.uber.org/zap"
)

type Amf struct {
	Logger      *zap.Logger
	AmfName     string
	GuamPlmn    uint32
	AmfRegionId uint16
	AmfSetId    uint32
	AmfPtr      uint32
	AmfCap      uint8
}

type AmfGNB struct {
	GranId uint32
	Tac    uint32
	Plmn   uint32
	AmfUEs map[ngap.AmfUeNgapIdType]AmfUE
}

type AmfUE struct {
	RanUeNgapId   uint32
	AmfUeNgapId   ngap.AmfUeNgapIdType
	SecCap        nas.SecCapType
	EaAlg         uint8
	IaAlg         uint8
	Authenticated bool
	RandToken     []byte
	Locations     []string
	PDUs          map[uint8]uint8
}
