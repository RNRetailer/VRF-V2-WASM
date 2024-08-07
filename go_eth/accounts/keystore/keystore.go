package keystore

import "errors"

var (
	ErrDecrypt = errors.New("could not decrypt key with given password")
)
