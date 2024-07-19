package fetcher

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/nodekey"
	"github.com/naoina/toml"
)

type NodeKeyFileFetcher struct {
	config nodekey.FileConfig
}

func NewNodeKeyFileFetcher(configBytes []byte) (*NodeKeyFileFetcher, error) {
	var data nodekey.FileConfig
	if err := toml.Unmarshal(configBytes, &data); err != nil {
		return nil, fmt.Errorf("invalid configuration passed: %w", err)
	}

	return &NodeKeyFileFetcher{
		data,
	}, nil
}

func (mgr *NodeKeyFileFetcher) FetchNodeKey() (*ecdsa.PrivateKey, error) {
	var (
		key *ecdsa.PrivateKey
		err error
	)
	switch {
	case mgr.config.File != "" && mgr.config.Hex != "":
		return nil, fmt.Errorf("options %q and %q are mutually exclusive", mgr.config.File, mgr.config.Hex)
	case mgr.config.File != "":
		if key, err = crypto.LoadECDSA(mgr.config.File); err != nil {
			return nil, fmt.Errorf("option %q: %w", mgr.config.File, err)
		}
		return key, nil
	case mgr.config.Hex != "":
		if key, err = crypto.HexToECDSA(mgr.config.Hex); err != nil {
			return nil, fmt.Errorf("option %q: %w", mgr.config.Hex, err)
		}
		return key, nil
	default:
		// autogenerate node key if no configurations are provided
		return nil, nil
	}
}

func (mgr *NodeKeyFileFetcher) FetchEncryptedNodeKey() (string, error) {
	switch {
	case mgr.config.File != "" && mgr.config.Hex != "":
		return "", fmt.Errorf("Options %q and %q are mutually exclusive", mgr.config.File, mgr.config.Hex)
	case mgr.config.File != "":
		b, err := os.ReadFile(mgr.config.File)
		if err != nil {
			return "", fmt.Errorf("Option %q: %w", mgr.config.File, err)
		}
		return string(b), nil
	case mgr.config.Hex != "":
		return mgr.config.Hex, nil
	default:
		return "", errors.New("unable to fetch file-based encrypted node key")
	}
}
