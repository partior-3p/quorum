package nodekey

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/cmd/utils/common"
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
	FetchNodeKey() *ecdsa.PrivateKey
	FetchEncryptedNodeKey() string
}

type Decrypter interface {
	DecryptNodeKey(data string) *ecdsa.PrivateKey
}

// retrieve unencrypted node key
func (mgr *Manager) GetNodeKey(isEncrypted bool) *ecdsa.PrivateKey {
	if isEncrypted {
		encryptedKey := mgr.fetcher.FetchEncryptedNodeKey()
		return mgr.decrypter.DecryptNodeKey(encryptedKey)
	} else {
		return mgr.fetcher.FetchNodeKey()
	}
}

func NewManager(source, decryptionScheme string, config []byte) *Manager {
	var fetch Fetcher
	var decrypt Decrypter

	// determine the source to fetch nodekey from
	switch {
	case source == constants.SourceFile:
		fetch = fetcher.NewNodeKeyFileFetcher(config)
	default:
		common.Fatalf("unsupported source type %q", source)
	}

	// determine the decrypter to be used
	switch {
	case decryptionScheme == constants.DecryptionNone:
		decrypt = decrypter.NewNodeKeyDefaultDecrypter(config)
	default:
		common.Fatalf("invalid decryption scheme %q", decryptionScheme)
	}

	return &Manager{
		fetch,
		decrypt,
	}
}
