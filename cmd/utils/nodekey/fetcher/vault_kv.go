package fetcher

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault-client-go"
)

type NodeKeyVaultKvFetcher struct {
	vault *common.VaultClient
}

func NewNodeKeyVaultKvFetcher(configBytes []byte) (*NodeKeyVaultKvFetcher, error) {
	vault, err := common.NewVaultClient(configBytes)
	return &NodeKeyVaultKvFetcher{vault}, err
}

// read the unencrypted nodekey
func (fetcher *NodeKeyVaultKvFetcher) FetchNodeKey() (*ecdsa.PrivateKey, error) {
	kvFetchKey := fetcher.vault.Config.KvFetchKey
	log.Info(fmt.Sprintf("Fetching node key from vault kv [%s] store [%s] key [%s]", fetcher.vault.Config.KvVersion, fetcher.vault.Config.KvPath, kvFetchKey))
	vaultResponseData, err := fetcher.fetch()
	if err != nil {
		return nil, err
	}
	if data, found := vaultResponseData[kvFetchKey]; found {
		if key, ok := data.(string); ok {
			if privateKey, err := crypto.HexToECDSA(key); err != nil {
				return nil, fmt.Errorf("unable to convert node key from kv store to private key: %w", err)
			} else {
				return privateKey, nil
			}
		} else {
			return nil, errors.New("node key is not a valid string in kv store")
		}
	}
	return nil, fmt.Errorf("unable to fetch node key from kv store in path [%s] with key [%s]", fetcher.vault.Config.KvPath, kvFetchKey)
}

// read the encrypted nodekey
func (fetcher *NodeKeyVaultKvFetcher) FetchEncryptedNodeKey() (string, error) {
	kvFetchKey := fetcher.vault.Config.KvFetchKey
	log.Info(fmt.Sprintf("Fetching encrypted node key from vault kv [%s] store [%s] key [%s]", fetcher.vault.Config.KvVersion, fetcher.vault.Config.KvPath, kvFetchKey))
	vaultResponseData, err := fetcher.fetch()
	if err != nil {
		return "", err
	}
	if data, found := vaultResponseData[kvFetchKey]; found {
		if key, ok := data.(string); ok {
			return key, nil
		} else {
			return "", errors.New("node key is not a valid string in kv store")
		}
	}
	return "", fmt.Errorf("unable to fetch node key from kv store in path [%s] with key [%s]", fetcher.vault.Config.KvPath, kvFetchKey)
}

// internal function to fetch data from vault into a map
func (fetcher *NodeKeyVaultKvFetcher) fetch() (vaultResponseData map[string]interface{}, err error) {
	ctx := context.Background()
	switch {
	case fetcher.vault.Config.KvVersion == "v1":
		resp, err := fetcher.vault.Client.Secrets.KvV1Read(ctx, fetcher.vault.Config.KvPath, vault.WithNamespace(fetcher.vault.Config.Namespace), vault.WithMountPath(fetcher.vault.Config.KvMount))
		if err != nil {
			return nil, fmt.Errorf("unable to fetch node key from kv store: %w", err)
		}
		vaultResponseData = resp.Data
	case fetcher.vault.Config.KvVersion == "v2":
		resp, err := fetcher.vault.Client.Secrets.KvV2Read(ctx, fetcher.vault.Config.KvPath, vault.WithNamespace(fetcher.vault.Config.Namespace), vault.WithMountPath(fetcher.vault.Config.KvMount))
		if err != nil {
			return nil, fmt.Errorf("unable to fetch node key from kv store: %w", err)
		}
		vaultResponseData = resp.Data.Data
	default:
		return nil, errors.New("unable to fetch node key from kv store")
	}
	return vaultResponseData, nil
}
