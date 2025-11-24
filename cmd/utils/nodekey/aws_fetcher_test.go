package nodekey

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/cmd/utils/common"
	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/decrypter"
	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/fetcher"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/stretchr/testify/require"
)

func TestGivenAwsSecretManagerConfiguredThenSuccessfullyGetNodeKeyFromAwsSecretManager(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	expectedNodeKeyString := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "secretsmanager.GetSecretValue").
			MatchJsonBody(`{"SecretId": "ptr1/quorum/nodekey", "VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846"}`).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD", 
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "` + expectedNodeKeyString + `"}`),
	)

	fmt.Println("Mock server running at:", mockedAwsUrl)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "f368ae7f-41e6-4d25-8e8e-a3aad0130846"
KmsKeyId = "alias/mykey"`

	fmt.Printf("Using config: %s\n", configToml)

	f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
	require.Nil(t, err)

	privateKey, err := f.FetchNodeKey()
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	expectedPrivateKey, ok := new(big.Int).SetString(expectedNodeKeyString, 16)
	require.True(t, ok)
	require.Equal(t, 0, privateKey.D.Cmp(expectedPrivateKey))
}

func TestGivenAwsSecretManagerConfiguredAndVersionIdIsNotProvidedThenGetNodeKeyFromAwsSecretManagerIsSuccessful(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	expectedNodeKeyString := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "secretsmanager.GetSecretValue").
			MatchExactJsonBody(map[string]string{"SecretId": "ptr1/quorum/nodekey"}).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD",
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "` + expectedNodeKeyString + `"}`),
	)

	fmt.Println("Mock server running at:", mockedAwsUrl)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = ""
KmsKeyId = "alias/mykey"`

	fmt.Printf("Using config: %s\n", configToml)

	f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
	require.Nil(t, err)

	privateKey, err := f.FetchNodeKey()
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	expectedPrivateKey, ok := new(big.Int).SetString(expectedNodeKeyString, 16)
	require.True(t, ok)
	require.Equal(t, 0, privateKey.D.Cmp(expectedPrivateKey))
}

func TestMockedKmsEncryptionDecryption(t *testing.T) {

	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Encrypt").
			Reply(200).
			MatchJsonBody(`{"KeyId":"alias/mykey2","Plaintext":"N2U3NjYwNTA0ZjUyMzRiOTRjNmJmODczZTA0ZjhhNjUwYWZlZWY4YTBhZmVkMThjNDVkNTk4MDE3YzQ3MjI1ZA=="}`).
			ResponseText(`{
				"CiphertextBlob": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ==",
				"KeyId": "arn:aws:kms:us-east-1:000000000000:key/9afe049f-571a-4f8e-b222-78c6c6e2557c"
			}`),
	)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Decrypt").
			Reply(200).
			MatchJsonBody(`{"KeyId":"alias/mykey2","CiphertextBlob":"OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}`).
			ResponseText(`{
				"KeyId":"arn:aws:kms:us-east-1:000000000000:key/9afe049f-571a-4f8e-b222-78c6c6e2557c",
				"Plaintext":"N2U3NjYwNTA0ZjUyMzRiOTRjNmJmODczZTA0ZjhhNjUwYWZlZWY4YTBhZmVkMThjNDVkNTk4MDE3YzQ3MjI1ZA=="
			}`),
	)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "AWSCURRENT"
KmsKeyId = "alias/mykey"`

	fmt.Printf("Using config: %s\n", configToml)

	client, err := common.NewAwsClient([]byte(configToml))

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	ctx := context.Background()

	plainText := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"
	kmsKeyId := "alias/mykey2"

	encResult, err := client.KMSClient.Encrypt(ctx, &kms.EncryptInput{
		Plaintext: []byte(plainText),
		KeyId:     aws.String(kmsKeyId),
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	base64CiphertextBlob := base64.StdEncoding.EncodeToString(encResult.CiphertextBlob)
	fmt.Printf("encryption ciphertext blob %s\n", base64CiphertextBlob)

	cipherTextBlob, _ := base64.StdEncoding.DecodeString(base64CiphertextBlob)
	decResult, _ := client.KMSClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: cipherTextBlob,
		KeyId:          aws.String(kmsKeyId),
	})

	fmt.Printf("decrypted plain text %s\n", decResult.Plaintext)

	require.Equal(t, plainText, string(decResult.Plaintext))
}

func TestGivenAwsSecretManagerNodeKeyIsEncyptedThenSuccessfullyGetNodeKeyAndDecryptFromAwsSecretManager(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	plainText := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"
	kmsKeyId := "alias/kms-quorum"
	secretId := "ptr1/quorum/nodekey"
	base64PlainText := base64.StdEncoding.EncodeToString([]byte(plainText))

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "secretsmanager.GetSecretValue").
			MatchJsonBody(`{"SecretId": "` + secretId + `"}`).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD", 
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}`),
	)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Decrypt").
			Reply(200).
			MatchJsonBody(`{"KeyId":"` + kmsKeyId + `","CiphertextBlob":"OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}`).
			ResponseText(`{
				"KeyId":"arn:aws:kms:us-east-1:000000000000:key/9afe049f-571a-4f8e-b222-78c6c6e2557c",
				"Plaintext":"` + base64PlainText + `"
			}`),
	)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "AWSCURRENT"
KmsKeyId = "` + kmsKeyId + `"`

	fmt.Printf("Using config: %s\n", configToml)

	f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
	require.Nil(t, err)

	base64EncryptedString, err := f.FetchEncryptedNodeKey()
	require.Nil(t, err)

	d, err := decrypter.NewNodeKeyAwsKmsDecrypter([]byte(configToml))
	require.Nil(t, err)

	privateKey, err := d.DecryptNodeKey(base64EncryptedString)
	require.Nil(t, err)
	require.NotNil(t, privateKey)

	expectedPrivateKey, ok := new(big.Int).SetString(plainText, 16)
	require.True(t, ok)
	require.Equal(t, 0, privateKey.D.Cmp(expectedPrivateKey))

}

func TestGivenAwsSecretManagerNodeKeyIsEncyptedWithRSA256AndEncriptionAlgoIsMissingThenDecryptionShouldFail(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	kmsKeyId := "alias/kms-quorum"
	secretId := "ptr1/quorum/nodekey"

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "secretsmanager.GetSecretValue").
			MatchJsonBody(`{"SecretId": "` + secretId + `"}`).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD", 
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}`),
	)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Decrypt").
			Reply(400).
			MatchExactJsonBody(map[string]string{"KeyId": kmsKeyId, "CiphertextBlob": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}).
			ResponseText(`{
				"__type":"InvalidCiphertextException",
				"message":"InvalidCiphertextException"
			}`),
	)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "AWSCURRENT"
KmsKeyId = "` + kmsKeyId + `"`

	fmt.Printf("Using config: %s\n", configToml)

	f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
	require.Nil(t, err)

	base64EncryptedString, err := f.FetchEncryptedNodeKey()
	require.Nil(t, err)

	d, err := decrypter.NewNodeKeyAwsKmsDecrypter([]byte(configToml))
	require.Nil(t, err)

	_, err = d.DecryptNodeKey(base64EncryptedString)
	require.ErrorContains(t, err, "InvalidCiphertextException")
}

func TestGivenAwsSecretManagerNodeKeyIsEncyptedWithRSA256AndEncriptionAlgoIsProvidedThenDecryptionShouldSucceed(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)
	setupMockedStsAuthEndpoint(mockSvc)

	plainText := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"
	kmsKeyId := "alias/kms-quorum"
	secretId := "ptr1/quorum/nodekey"
	base64PlainText := base64.StdEncoding.EncodeToString([]byte(plainText))

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "secretsmanager.GetSecretValue").
			MatchJsonBody(`{"SecretId": "` + secretId + `"}`).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD", 
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}`),
	)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Decrypt").
			Reply(400).
			MatchExactJsonBody(map[string]string{"KeyId": kmsKeyId, "CiphertextBlob": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}).
			ResponseText(`{
				"__type":"InvalidCiphertextException",
				"message":"InvalidCiphertextException"
			}`),
	)

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeader("X-Amz-Target", "TrentService.Decrypt").
			Reply(200).
			MatchExactJsonBody(map[string]string{"KeyId": kmsKeyId, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "CiphertextBlob": "OWFmZTA0OWYtNTcxYS00ZjhlLWIyMjItNzhjNmM2ZTI1NTdj6ErJUzMhvsbKDFM7EqxC9QhTdOVXpbmrNoVdPsk7kokVCpHbcNMop9CbixeyE6HC62mnu1s6IU3C24qP5dpvqbOH/GChYEZEpxYA2o/ZUHXb9C8rS0y/eZjqL5LlBkw0ee+6DxY0UoXFMSXPc34ehQ=="}).
			ResponseText(`{
				"KeyId":"arn:aws:kms:us-east-1:000000000000:key/9afe049f-571a-4f8e-b222-78c6c6e2557c",
				"Plaintext":"` + base64PlainText + `"
			}`),
	)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "AWSCURRENT"
KmsKeyId = "` + kmsKeyId + `"
KmsEncryptionAlgorithm = "RSAES_OAEP_SHA_256"`

	fmt.Printf("Using config: %s\n", configToml)

	f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
	require.Nil(t, err)

	base64EncryptedString, err := f.FetchEncryptedNodeKey()
	require.Nil(t, err)

	d, err := decrypter.NewNodeKeyAwsKmsDecrypter([]byte(configToml))
	require.Nil(t, err)

	_, err = d.DecryptNodeKey(base64EncryptedString)
	require.Nil(t, err)
}

func setupMockedStsAuthEndpoint(mockSvc *tests.MockServer) {
	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeaderMatchRegex("Content-Type", "^application/x[-]www[-]form[-]urlencoded").
			MatchBodyRegex("Action[=]AssumeRoleWithWebIdentity").
			Reply(200).
			ResponseText(`<?xml version='1.0' encoding='utf-8'?>
			<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>LSIARZPUZDIKOE2FJGLH</AccessKeyId><SecretAccessKey>oupr5kXKuXBZ4wK7wjEylFmjxPC59YVQ43tbvDcR</SecretAccessKey><SessionToken>FQoGZXIvYXdzEBYaDrnmHIg9HvVsuJPfO2vGEmnLFk/IpnQ194Sr24f9u/YlDLJ33aLvk1Xd8sm1v3vsux46MwUnrFQqUp5oQGTvcibWyZhIEAXlD3cnPBw9ZHBpW0q1CJzXCVGgty85gmr/mOq/t5nogagIvfQ8uCJprQDaHFTpGjJlFiaraMGUKwFqkuvl2dgTPjXu9e3Jghf2/NKJFv8MB+ARP9UA/+o8o8KR2bEQ5ABePtxf3o0K3Y2sYVyWi/R5JMMhhfI8NRFcc8Wuckg+UQc4VcUmkw+b7FZJ7V57ipyrcRbWn+Sh/pEhNyHs6NxTr0sZ9m7SLCTnQW2IHH4wTdoCXLiS4d0=</SessionToken><Expiration>2025-05-30T10:32:38.242000Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>ARO123EXAMPLE123:aws-sdk-java-1748594391789</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/my-test-role/aws-sdk-java-1748594391789</Arn></AssumedRoleUser><PackedPolicySize>6</PackedPolicySize></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>ae43f871-fae3-4858-9525-a7ce0c39e72e</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`),
	)
}
