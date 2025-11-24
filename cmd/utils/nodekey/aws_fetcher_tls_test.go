package nodekey

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/decrypter"
	"github.com/ethereum/go-ethereum/cmd/utils/nodekey/fetcher"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/stretchr/testify/require"
)

const (
	FilePermUserReadWriteAllRead = 0o644 // rw-r--r--
)

func TestGivenAwsMockServerUseTlsAndConfigureQuorumSslCertDirEnvVarThenGetNodeKeyFromAwsSuccessful(t *testing.T) {
	mockSvc := tests.NewMockTLSServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()

	caCertFile := mockSvc.CertificateFile()
	setupSslCertDir(t, caCertFile)

	plainText := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"
	kmsKeyId := "alias/kms-quorum"
	secretId := "ptr1/quorum/nodekey"

	setupAwsMockServiceResponses(mockSvc, secretId, kmsKeyId, plainText)
	tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)

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

func TestGivenAwsMockServerUseTlsAndMissingSslCertDirEnvVarThenGetNodeKeyFromAwsShouldFail(t *testing.T) {

	if os.Getenv("CHILD_TEST") == "1" {
		mockSvc := tests.NewMockTLSServer()
		defer mockSvc.Close()

		mockedAwsUrl := mockSvc.URL()

		plainText := "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"
		kmsKeyId := "alias/kms-quorum"
		secretId := "ptr1/quorum/nodekey"

		setupAwsMockServiceResponses(mockSvc, secretId, kmsKeyId, plainText)
		tests.SetupMockAwsEnvironmentUsingWebToken(t, mockedAwsUrl)

		tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
		tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

		configToml := `SecretName = "ptr1/quorum/nodekey"
	SecretVersion = "AWSCURRENT"
	KmsKeyId = "` + kmsKeyId + `"`

		fmt.Printf("Using config: %s\n", configToml)

		f, err := fetcher.NewNodeKeyAwsSecretsManagerFetcher([]byte(configToml))
		require.Nil(t, err)

		data, err := f.FetchEncryptedNodeKey()
		require.Empty(t, data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "tls: failed to verify certificate: x509: certificate signed by unknown authority")
		return
	}

	tests.UnsetTestEnv(t, "SSL_CERT_DIR")
	cmd := exec.Command(os.Args[0], "-test.run=TestGivenAwsMockServerUseTlsAndMissingSslCertDirEnvVarThenGetNodeKeyFromAwsShouldFail")
	cmd.Env = append(os.Environ(), "CHILD_TEST=1")
	out, err := cmd.CombinedOutput()

	fmt.Printf("Command output:\n%s\n", out)
	require.NoError(t, err, "expected subprocess to successfully fail if SSL_CERT_DIR is undefined")

}

func setupAwsMockServiceResponses(mockSvc *tests.MockServer, secretId string, kmsKeyId string, plainText string) {
	base64PlainText := base64.StdEncoding.EncodeToString([]byte(plainText))

	mockSvc.RegisterMock(
		mockSvc.MockHttpPath("/").
			Post().
			MatchHeaderMatchRegex("Content-Type", "^application/x[-]www[-]form[-]urlencoded").
			MatchBodyRegex("Action[=]AssumeRoleWithWebIdentity").
			Reply(200).
			ResponseText(`<?xml version='1.0' encoding='utf-8'?>
			<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>LSIARZPUZDIKOE2FJGLH</AccessKeyId><SecretAccessKey>oupr5kXKuXBZ4wK7wjEylFmjxPC59YVQ43tbvDcR</SecretAccessKey><SessionToken>FQoGZXIvYXdzEBYaDrnmHIg9HvVsuJPfO2vGEmnLFk/IpnQ194Sr24f9u/YlDLJ33aLvk1Xd8sm1v3vsux46MwUnrFQqUp5oQGTvcibWyZhIEAXlD3cnPBw9ZHBpW0q1CJzXCVGgty85gmr/mOq/t5nogagIvfQ8uCJprQDaHFTpGjJlFiaraMGUKwFqkuvl2dgTPjXu9e3Jghf2/NKJFv8MB+ARP9UA/+o8o8KR2bEQ5ABePtxf3o0K3Y2sYVyWi/R5JMMhhfI8NRFcc8Wuckg+UQc4VcUmkw+b7FZJ7V57ipyrcRbWn+Sh/pEhNyHs6NxTr0sZ9m7SLCTnQW2IHH4wTdoCXLiS4d0=</SessionToken><Expiration>2025-05-30T10:32:38.242000Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>ARO123EXAMPLE123:aws-sdk-java-1748594391789</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/my-test-role/aws-sdk-java-1748594391789</Arn></AssumedRoleUser><PackedPolicySize>6</PackedPolicySize></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>ae43f871-fae3-4858-9525-a7ce0c39e72e</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`),
	)

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
}

func setupSslCertDir(t *testing.T, certFile string) string {
	tmpDir := t.TempDir()
	dstCertPath := filepath.Join(tmpDir, "mock-aws-ca-cert.pem")

	input, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	err = os.WriteFile(dstCertPath, input, FilePermUserReadWriteAllRead)
	if err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	tests.SetTestEnv(t, "SSL_CERT_DIR", tmpDir)

	return tmpDir
}
