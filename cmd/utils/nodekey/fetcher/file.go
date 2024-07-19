package fetcher

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"

	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type NodeKeyFileFetcher struct {
	config FileConfigData
}

type FileConfigData struct {
	Hex  string `json:"hex,omitempty"`
	File string `json:"file,omitempty"`
}

func NewNodeKeyFileFetcher(configBytes []byte) *NodeKeyFileFetcher {
	var data FileConfigData
	if err := json.Unmarshal(configBytes, &data); err != nil {
		common.Fatalf("invalid configuration passed: %v", err)
	}

	return &NodeKeyFileFetcher{
		data,
	}
}

func (mgr *NodeKeyFileFetcher) FetchNodeKey() *ecdsa.PrivateKey {
	var (
		key *ecdsa.PrivateKey
		err error
	)
	switch {
	case mgr.config.File != "" && mgr.config.Hex != "":
		common.Fatalf("Options %q and %q are mutually exclusive", mgr.config.File, mgr.config.Hex)
	case mgr.config.File != "":
		if key, err = crypto.LoadECDSA(mgr.config.File); err != nil {
			common.Fatalf("Option %q: %v", mgr.config.File, err)
		}
		return key
	case mgr.config.Hex != "":
		if key, err = crypto.HexToECDSA(mgr.config.Hex); err != nil {
			common.Fatalf("Option %q: %v", mgr.config.Hex, err)
		}
		return key
	}
	return nil
}

func (mgr *NodeKeyFileFetcher) FetchEncryptedNodeKey() string {
	switch {
	case mgr.config.File != "" && mgr.config.Hex != "":
		common.Fatalf("Options %q and %q are mutually exclusive", mgr.config.File, mgr.config.Hex)
	case mgr.config.File != "":
		b, err := os.ReadFile(mgr.config.File)
		if err != nil {
			common.Fatalf("Option %q: %v", mgr.config.File, err)
		}
		return string(b)
	case mgr.config.Hex != "":
		return mgr.config.Hex
	}
	return ""
}
