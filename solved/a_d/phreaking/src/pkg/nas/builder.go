package nas

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"phreaking/internal/crypto"
)

func BuildMessagePlain[T any](msgPtr *T) (encMsg []byte, mac [8]byte, err error) {
	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	err = e.Encode(&msgPtr)
	return b.Bytes(), mac, err
}

func BuildMessage[T any](EA uint8, IA uint8, msgPtr *T) (encMsg []byte, mac [8]byte, err error) {
	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	err = e.Encode(&msgPtr)
	if err != nil {
		return b.Bytes(), mac, err
	}

	msg := b.Bytes()
	encMsg, err = crypto.Encrypt(EA, msg)
	if err != nil {
		return msg, mac, err
	}

	alg, ok := crypto.IAalg[IA]
	if !ok {
		return encMsg, mac, fmt.Errorf("integrity alg %d is not implemented", IA)
	}

	copy(mac[:], alg(encMsg)[:8])
	return encMsg, mac, nil
}
