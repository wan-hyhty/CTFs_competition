package nas

import "github.com/gofrs/uuid"

type NasMsgType int
type AmfUeNgapIdType uuid.UUID

const (
	NASRegRequest NasMsgType = iota
	NASIdRequest
	NASIdResponse
	NASAuthRequest
	NASAuthResponse
	NASSecurityModeCommand
	NASSecurityModeComplete
	InitialContextSetupRequestRegAccept
	UECapInfoIndication
	InitialContextSetupResponse
	RegisterComplete
	PDUSessionEstRequest
	PDUSessionEstAccept
	PDUReq
	PDURes
	PDUSessionResourceReleaseCommand
	// Location
	LocationUpdate
	LocationReportRequest
	LocationReportResponse
)

type EaMask uint8

const (
	EA0 EaMask = 1 << iota
	EA1
	EA2
	EA3
	EA4
	EA5
	EA6
	EA7
)

var EaMaskMap = []EaMask{
	EA0,
	EA1,
	EA2,
	EA3,
	EA4,
	EA5,
	EA6,
	EA7,
}

type IaMask uint8

const (
	IA0 IaMask = 1 << iota
	IA1
	IA2
	IA3
	IA4
	IA5
	IA6
	IA7
)

var IaMaskMap = []IaMask{
	IA0,
	IA1,
	IA2,
	IA3,
	IA4,
	IA5,
	IA6,
	IA7,
}

type SecCapType struct {
	// 	1  |  2  | .. |  8
	// EA0 | EA1 | .. | EA7
	EaCap EaMask
	// 	1  |  2  | .. |  8
	// IA0 | IA1 | .. | IA7
	IaCap IaMask
}

type GmmHeader struct {
	// MobileId MobileIdType
	Security    bool
	Mac         [8]byte
	MessageType NasMsgType
	Message     []byte
}

type MobileIdType struct {
	Mcc        uint8
	Mnc        uint8
	HomeNetPki uint8
	Msin       uint
}

type NASRegRequestMsg struct {
	// Extended protocol discriminator
	// 5GS registration type
	// ngKsi
	MobileId MobileIdType
	SecCap   SecCapType
}

type NASAuthRequestMsg struct {
	Rand     []byte
	AuthRand []byte
	Auth     []byte
}

type NASAuthResponseMsg struct {
	Res []byte
}

type NASSecurityModeCommandMsg struct {
	EaAlg        uint8
	IaAlg        uint8
	ReplaySecCap SecCapType
}

type PDUSessionEstRequestMsg struct {
	PduSesId   uint8
	PduSesType uint8
}

type PDUSessionEstAcceptMsg struct {
	PduSesId uint8
	// PduAddress []byte
	// SSC
	// QoS
	// AMBR
}

type LocationUpdateMsg struct {
	Location string
}

type LocationReportRequestMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
}

type LocationReportResponseMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
	Locations   []string
}

type PDUReqMsg struct {
	PduSesId uint8
	Request  []byte
}
type PDUResMsg struct {
	PduSesId uint8
	Response []byte
}
