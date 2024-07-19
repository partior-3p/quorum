package common

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/p2p/nodekey"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/naoina/toml"
)

const (
	VAULT_ROOT_TOKEN      = "VAULT_ROOT_TOKEN"
	VAULT_APP_ROLE_ID     = "VAULT_APP_ROLE_ID"
	VAULT_APP_ROLE_SECRET = "VAULT_APP_ROLE_SECRET"
)

type VaultClient struct {
	Config nodekey.VaultConfig
	Client *vault.Client
}

func NewVaultClient(configBytes []byte) (*VaultClient, error) {
	ctx := context.Background()
	var data nodekey.VaultConfig
	if err := toml.Unmarshal(configBytes, &data); err != nil {
		return nil, fmt.Errorf("invalid configuration passed: %w", err)
	}

	if data.KvVersion != "v1" && data.KvVersion != "v2" {
		return nil, errors.New("invalid kv version configuration passed, only accepts (v1|v2)")
	}

	if data.KvFetchKey == "" {
		return nil, errors.New("need to specify default key to retrieve data from kv store")
	}

	if data.Url == "" {
		return nil, errors.New("need to specify vault url")
	}

	vaultOptions := []vault.ClientOption{
		vault.WithAddress(data.Url),
		vault.WithRequestTimeout(30 * time.Second),
		vault.WithEnvironment(),
	}

	// one way tls
	if data.VaultTlsServerCertPath != "" {
		tls := vault.TLSConfiguration{}
		tls.ServerCertificate.FromFile = data.VaultTlsServerCertPath
		vaultOptions = append(vaultOptions, vault.WithTLS(tls))
	}

	client, err := vault.New(vaultOptions...)

	if err != nil {
		return nil, fmt.Errorf("unable to create vault client: %w", err)
	}

	// environment variables take precedence over toml configuration
	if rootToken := os.Getenv(VAULT_ROOT_TOKEN); rootToken != "" {
		data.Token = rootToken
	}
	if appRoleId := os.Getenv(VAULT_APP_ROLE_ID); appRoleId != "" {
		data.AppRoleId = appRoleId
	}
	if appRoleSecret := os.Getenv(VAULT_APP_ROLE_SECRET); appRoleSecret != "" {
		data.AppRoleSecret = appRoleSecret
	}

	// only support root token or app role authentication (root token takes precedence if both are specified)
	if data.Token != "" {
		if err := client.SetToken(data.Token); err != nil {
			return nil, fmt.Errorf("unable to authenticate with token: %w", err)
		}
	} else {
		appRolePath := data.AppRolePath
		if appRolePath == "" {
			appRolePath = "approle"
		}
		resp, err := client.Auth.AppRoleLogin(
			ctx,
			schema.AppRoleLoginRequest{
				RoleId:   data.AppRoleId,
				SecretId: data.AppRoleSecret,
			},
			vault.WithMountPath(appRolePath),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to login to vault via app role: %w", err)
		}
		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			return nil, fmt.Errorf("unable to set app role token in vault client: %w", err)
		}
	}

	return &VaultClient{
		data,
		client,
	}, nil
}
