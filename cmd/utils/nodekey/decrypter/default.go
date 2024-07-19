package decrypter

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/cmd/utils/common"
)

// default decrypter have no decryption capabilities
type NodeKeyDefaultDecrypter struct{}

func NewNodeKeyDefaultDecrypter(configBytes []byte) *NodeKeyDefaultDecrypter {
	return &NodeKeyDefaultDecrypter{}
}

func (d *NodeKeyDefaultDecrypter) DecryptNodeKey(data string) *ecdsa.PrivateKey {
	common.Fatalf("default decrypter cannot perform decryption")
	return nil
}