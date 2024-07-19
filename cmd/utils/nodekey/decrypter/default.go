package decrypter

import (
	"crypto/ecdsa"
	"errors"
)

// default decrypter have no decryption capabilities
type NodeKeyDefaultDecrypter struct{}

func NewNodeKeyDefaultDecrypter(configBytes []byte) (*NodeKeyDefaultDecrypter, error) {
	return &NodeKeyDefaultDecrypter{}, nil
}

func (d *NodeKeyDefaultDecrypter) DecryptNodeKey(data string) (*ecdsa.PrivateKey, error) {
	return nil, errors.New("default decrypter cannot perform decryption")
}
