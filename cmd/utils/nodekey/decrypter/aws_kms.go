package decrypter

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

type NodeKeyAwsKmsDecrypter struct {
	aws *common.AwsClient
}

func NewNodeKeyAwsKmsDecrypter(configBytes []byte) (*NodeKeyAwsKmsDecrypter, error) {
	awsClient, err := common.NewAwsClient(configBytes)
	return &NodeKeyAwsKmsDecrypter{aws: awsClient}, err
}

func (decrypter *NodeKeyAwsKmsDecrypter) DecryptNodeKey(base64StringData string) (*ecdsa.PrivateKey, error) {
	ctx := context.Background()

	if decrypter.aws.Config.KmsKeyId == "" {
		return nil, errors.New("configuration [KmsKeyId] should not be empty")
	}

	log.Info(fmt.Sprintf("Decrypting node key with AWS KMS using KmsKeyId [%s]", decrypter.aws.Config.KmsKeyId))

	bytesData, err := base64.StdEncoding.DecodeString(base64StringData)
	if err != nil {
		return nil, err
	}

	input := &kms.DecryptInput{
		CiphertextBlob: bytesData,
		KeyId:          aws.String(decrypter.aws.Config.KmsKeyId),
	}

	if decrypter.aws.Config.KmsEncryptionAlgorithm != "" {
		var err error
		input.EncryptionAlgorithm, err = decrypter.getEncryptionAlgorithmSpec(decrypter.aws.Config.KmsEncryptionAlgorithm)
		if err != nil {
			return nil, err
		}
	}

	result, err := decrypter.aws.KMSClient.Decrypt(ctx, input)

	if err != nil {
		return nil, err
	}

	if result != nil {
		if privateKey, err := crypto.HexToECDSA(string(result.Plaintext)); err != nil {
			return nil, fmt.Errorf("unable to convert node key data to private key. Error: %w", err)
		} else {
			return privateKey, nil
		}
	}
	return nil, fmt.Errorf("unable to decrypt node key using AWS KMS using KeyId [%s]", decrypter.aws.Config.KmsKeyId)
}

func (decrypter *NodeKeyAwsKmsDecrypter) getEncryptionAlgorithmSpec(algo string) (types.EncryptionAlgorithmSpec, error) {
	for _, val := range types.EncryptionAlgorithmSpec("").Values() {
		if string(val) == algo {
			return val, nil
		}
	}
	return "", fmt.Errorf("unsupported encryption algorithm: %s", algo)
}
