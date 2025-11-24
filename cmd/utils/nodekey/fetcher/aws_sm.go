package fetcher

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

type NodeKeyAwsSecretsManagerFetcher struct {
	aws *common.AwsClient
}

func NewNodeKeyAwsSecretsManagerFetcher(configBytes []byte) (*NodeKeyAwsSecretsManagerFetcher, error) {
	awsClient, err := common.NewAwsClient(configBytes)
	return &NodeKeyAwsSecretsManagerFetcher{aws: awsClient}, err
}

func (fetcher *NodeKeyAwsSecretsManagerFetcher) FetchNodeKey() (*ecdsa.PrivateKey, error) {
	secretData, err := fetcher.fetch()
	if err != nil {
		return nil, err
	}

	if privateKey, err := crypto.HexToECDSA(secretData); err != nil {
		return nil, fmt.Errorf("unable to convert node key from secret manager to private key. Error: %w", err)
	} else {
		return privateKey, nil
	}
}

func (fetcher *NodeKeyAwsSecretsManagerFetcher) FetchEncryptedNodeKey() (string, error) {
	secretData, err := fetcher.fetch()
	if err != nil {
		return "", err
	}

	return secretData, nil
}

func (fetcher *NodeKeyAwsSecretsManagerFetcher) fetch() (string, error) {
	secretName := fetcher.aws.Config.SecretName
	secretVersionId := fetcher.aws.Config.SecretVersion

	log.Info(fmt.Sprintf("Fetching node key from AWS secret manager using key [%s]", secretName))

	secretManagerInputValue := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	if secretVersionId != "" {
		secretManagerInputValue.VersionId = aws.String(secretVersionId)
	}

	ctx := context.Background()
	responseData, err := fetcher.aws.SecretsClient.GetSecretValue(ctx, secretManagerInputValue)

	if err != nil {
		return "", err
	}

	if responseData.SecretString == nil || *responseData.SecretString == "" {
		return "", fmt.Errorf("using key [%s], data from secret manager is empty", secretName)
	}

	return *responseData.SecretString, nil
}
