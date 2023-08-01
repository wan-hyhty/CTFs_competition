package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var key = []byte(string(os.Getenv("PHREAKING_SIM_KEY")))

func ComputeHash(input []byte) (hash string) {
	h := sha256.New()
	h.Write(input)
	bs := h.Sum(nil)
	return string(bs)
}

func EncryptAES(input []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmInstance.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ct := gcmInstance.Seal(nil, nonce, input, nil)
	nonceSize := len(nonce)
	bufSize := len(ct) + nonceSize + 1
	buf := make([]byte, bufSize)
	buf[0] = byte(nonceSize)
	copy(buf[1:1+nonceSize], nonce)
	copy(buf[1+nonceSize:], ct)
	return buf, nil
}

func DecryptAES(ct []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	nonceSize := int(ct[0])
	nonce, cipheredText := ct[1:1+nonceSize], ct[1+nonceSize:]
	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		return nil, err
	}
	return originalText, nil
}

func Decrypt(EA uint8, msgbuf []byte) ([]byte, error) {
	if EA == 0 {
		return msgbuf, nil
	} else if EA == 1 {
		return DecryptAES(msgbuf)
	}
	return nil, fmt.Errorf("encryption alg %d is not supported", EA)
}

func Encrypt(EA uint8, msgbuf []byte) ([]byte, error) {
	if EA == 0 {
		return msgbuf, nil
	} else if EA == 1 {
		return EncryptAES(msgbuf)
	}
	return nil, fmt.Errorf("encryption alg %d is not supported", EA)
}

func CheckIntegrity(IA uint8, buf []byte, mac [8]byte) error {
	switch {
	case IA == 0:
		return errors.New("null integrity is not allowed")
	case IA < 5:
		alg, ok := IAalg[IA]
		if !ok {
			return fmt.Errorf("integrity alg %d is not implemented", IA)
		}
		if !bytes.Equal(mac[:], alg(buf)[:8]) {
			return errors.New("integrity check failed")
		} else {
			return nil
		}
	default:
		return fmt.Errorf("integrity alg %d is not implemented", IA)
	}
}

func IA0(msg []byte) (mac []byte) {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}

func IA1(msg []byte) (mac []byte) {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA2(msg []byte) (mac []byte) {
	hash := hmac.New(sha512.New, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA3(msg []byte) (mac []byte) {
	hash := hmac.New(sha3.New256, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA4(msg []byte) (mac []byte) {
	hash, _ := blake2b.New256(key)
	hash.Write(msg)
	return hash.Sum(nil)
}

var IAalg = map[uint8]func([]byte) []byte{0: IA0, 1: IA1, 2: IA2, 3: IA3, 4: IA4}
