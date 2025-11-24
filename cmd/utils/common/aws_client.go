package common

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/ethereum/go-ethereum/p2p/nodekey"
	"github.com/naoina/toml"
)

type AwsClient struct {
	Config        nodekey.AwsConfig
	SecretsClient *secretsmanager.Client
	KMSClient     *kms.Client
}

/*
The following environment variables are required by the AWS SDK to successfully authenticate via web token id:

	AWS_WEB_IDENTITY_TOKEN_FILE - The temporery web token injected automatically to k8s pod via IRSA setup
	AWS_ROLE_ARN - The corresponding role injected automatically to k8s pod via IRSA setup
	AWS_REGION - injected automatically to k8s pod via IRSA setup
*/
func NewAwsClient(configBytes []byte) (*AwsClient, error) {

	ctx := context.Background()
	var cfg nodekey.AwsConfig
	if err := toml.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration passed: %w", err)
	}

	if err := validateConfigurationValues(cfg); err != nil {
		return nil, err
	}

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	secretsClient := secretsmanager.NewFromConfig(awsConfig)

	kmsClient := kms.NewFromConfig(awsConfig)

	return &AwsClient{
		SecretsClient: secretsClient,
		KMSClient:     kmsClient,
		Config:        cfg,
	}, nil
}

func validateConfigurationValues(config nodekey.AwsConfig) error {

	if config.SecretName == "" {
		return errors.New("need to specify secret's name to retrieve data from AWS secret manager")
	}

	return nil
}
