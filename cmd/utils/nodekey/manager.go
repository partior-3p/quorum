package nodekey

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/constants"
	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/decrypter"
	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/fetcher"
)

// Manager represents a nodekey manager that can do the following
// fetch node key (encrypted|unencrypted) from various sources (file|vault)
// decrypt encrypted node key via different mechanisms (none|vault tse)
type Manager struct {
	fetcher   Fetcher
	decrypter Decrypter
}

type Fetcher interface {
	// retrieve node key in hex or encrypted form
	FetchNodeKey() (*ecdsa.PrivateKey, error)
	FetchEncryptedNodeKey() (string, error)
}

type Decrypter interface {
	DecryptNodeKey(data string) (*ecdsa.PrivateKey, error)
}

// retrieve unencrypted node key
func (mgr *Manager) GetNodeKey(isEncrypted bool) (*ecdsa.PrivateKey, error) {
	if isEncrypted {
		if encryptedKey, err := mgr.fetcher.FetchEncryptedNodeKey(); err != nil {
			return nil, err
		} else {
			return mgr.decrypter.DecryptNodeKey(encryptedKey)
		}
	} else {
		return mgr.fetcher.FetchNodeKey()
	}
}

func NewManager(source, decryptionScheme string, config []byte) (*Manager, error) {
	var fetch Fetcher
	var decrypt Decrypter
	var err error

	// determine the source to fetch nodekey from
	switch {
	case source == constants.SourceFile:
		fetch, err = fetcher.NewNodeKeyFileFetcher(config)
	case source == constants.SourceVaultKv:
		fetch, err = fetcher.NewNodeKeyVaultKvFetcher(config)
	default:
		return nil, fmt.Errorf("unsupported source type %q", source)
	}
	if err != nil {
		return nil, err
	}

	// determine the decrypter to be used
	switch {
	case decryptionScheme == constants.DecryptionNone:
		decrypt, err = decrypter.NewNodeKeyDefaultDecrypter(config)
	case decryptionScheme == constants.DecryptionVaultTse:
		decrypt, err = decrypter.NewNodeKeyVaultTseDecrypter(config)
	default:
		return nil, fmt.Errorf("invalid decryption scheme %q", decryptionScheme)
	}
	if err != nil {
		return nil, err
	}

	return &Manager{
		fetch,
		decrypt,
	}, nil
}
