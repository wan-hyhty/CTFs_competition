package parser

import (
	"bytes"
	"encoding/gob"
)

// Generic message decoder
func DecodeMsg[T any](buf []byte, msgPtr *T) error {
	reader := bytes.NewReader(buf)
	dec := gob.NewDecoder(reader)
	return dec.Decode(&msgPtr)
}

func EncodeMsg[T any](msgPtr *T) ([]byte, error) {
	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	err := e.Encode(&msgPtr)
	return b.Bytes(), err
}
