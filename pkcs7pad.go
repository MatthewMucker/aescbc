// This file is taken from code snippets published online by William Gallagher
// and is republished here in a good-faith belief that Mr. Gallagher intended
// his code to be re-used by others.

package aescbc

import (
	"errors"
)

func Pkcs7Pad(input []byte, blockSize int) []byte {
	r := len(input) % blockSize
	pl := blockSize - r
	for i := 0; i < pl; i++ {
		input = append(input, byte(pl))
	}
	return input
}

func Pkcs7Unpad(input []byte) ([]byte, error) {
	if input == nil || len(input) == 0 {
		return nil, nil
	}

	pc := input[len(input)-1]
	pl := int(pc)
	err := checkPaddingIsValid(input, pl)
	if err != nil {
		return nil, err
	}
	return input[:len(input)-pl], nil
}

func checkPaddingIsValid(input []byte, paddingLength int) error {
	if len(input) < paddingLength {
		return errors.New("invalid padding")
	}
	p := input[len(input)-(paddingLength):]
	for _, pc := range p {
		if uint(pc) != uint(len(p)) {
			return errors.New("invalid padding")
		}
	}
	return nil
}
