package ue

import (
	"bufio"
	"os"
	"phreaking/pkg/nas"

	"go.uber.org/zap"
)

type UE struct {
	Logger *zap.Logger
	state  StateType
	//MobileId ngap.MobileIdType
	SecCap      nas.SecCapType
	EaAlg       uint8
	IaAlg       uint8
	ActivePduId uint8
}

func NewUE(logger *zap.Logger) *UE {
	return &UE{Logger: logger, state: Deregistered}
}

func (u *UE) GetState(s StateType) StateType {
	return u.state
}

func (u *UE) ToState(s StateType) {
	u.Logger.Sugar().Debugf("To state: %s", s)
	u.state = s
}

func (u *UE) InState(s StateType) bool {
	return (u.state == s)
}

func (u *UE) GetLocation() (string, error) {
	u.Logger.Sugar().Debugf("Getting location from UE OS API")
	location := ""
	readFile, err := os.Open("/service/data/location.data")
	if err != nil {
		return location, err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		location = fileScanner.Text()
	}
	readFile.Close()
	return location, nil
}

type StateType string

// state for UE
const (
	Deregistered          StateType = "Deregistered"
	RegistrationInitiated StateType = "RegistrationInitiated"
	Authentication        StateType = "Authentication"
	SecurityMode          StateType = "SecurityMode"
	ContextSetup          StateType = "ContextSetup"
	Registered            StateType = "Registered"
)
