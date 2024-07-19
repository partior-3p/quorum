package decrypter

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type NodeKeyVaultTseDecrypter struct {
	vault *common.VaultClient
}

func NewNodeKeyVaultTseDecrypter(configBytes []byte) (*NodeKeyVaultTseDecrypter, error) {
	vault, err := common.NewVaultClient(configBytes)
	return &NodeKeyVaultTseDecrypter{vault}, err
}

func (decrypter *NodeKeyVaultTseDecrypter) DecryptNodeKey(data string) (*ecdsa.PrivateKey, error) {
	log.Info(fmt.Sprintf("Decrypting node key with vault transit secret engine key [%s] mount [%s]", decrypter.vault.Config.TseKeyName, decrypter.vault.Config.TseMount))
	ctx := context.Background()

	req := schema.TransitDecryptRequest{Ciphertext: data}
	resp, err := decrypter.vault.Client.Secrets.TransitDecrypt(ctx, decrypter.vault.Config.TseKeyName, req, vault.WithNamespace(decrypter.vault.Config.Namespace), vault.WithMountPath(decrypter.vault.Config.TseMount))

	if err != nil {
		return nil, fmt.Errorf("unable to decrypt node key from transit secret engine: %w", err)
	}

	if data, found := resp.Data["plaintext"]; found {
		if key, ok := data.(string); ok {
			keyBytes, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				return nil, fmt.Errorf("unable to decode base64 node key: %w", err)
			}
			if privateKey, err := crypto.HexToECDSA(string(keyBytes)); err != nil {
				return nil, fmt.Errorf("unable to convert transit secret engine decrypted node key to private key: %w", err)
			} else {
				return privateKey, nil
			}
		} else {
			common.Fatalf("node key is not a valid string after decrypting in transit secret engine")
		}
	}
	return nil, fmt.Errorf("unable to decrypt node key with vault transit secret engine key [%s] mount [%s]", decrypter.vault.Config.TseKeyName, decrypter.vault.Config.TseMount)
}
