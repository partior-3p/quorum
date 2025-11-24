package common

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/stretchr/testify/require"
)

func TestNewAwsClientUsingConfig(t *testing.T) {
	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "AWSCURRENT"
KmsKeyId = "alias/mykey"`

	fmt.Printf("Using config: %s\n", configToml)

	client, err := NewAwsClient([]byte(configToml))

	require.NotNil(t, client, "client should be nil")
	require.Nil(t, err, "Error should be nil")

	require.Equal(t, client.Config.SecretName, "ptr1/quorum/nodekey")
	require.Equal(t, client.Config.SecretVersion, "AWSCURRENT")
	require.Equal(t, client.Config.KmsKeyId, "alias/mykey")
}

func TestAwsServerProxyGetSecret(t *testing.T) {
	mockSvc := tests.NewMockServer()
	defer mockSvc.Close()

	mockedAwsUrl := mockSvc.URL()
	setupMockAwsEnvironmentUsingWebToken(t)

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
			MatchJsonBody(`{"SecretId": "ptr1/quorum/nodekey", "VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846"}`).
			Reply(200).
			ResponseText(`{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:ptr1/quorum/nodekey-qPfliD", 
			"Name": "ptr1/quorum/nodekey", 
			"VersionId": "f368ae7f-41e6-4d25-8e8e-a3aad0130846", 
			"VersionStages": ["AWSCURRENT"], 
			"CreatedDate": 1743129842.0, 
			"SecretString": "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d"}`),
	)
	ctx := context.Background()

	fmt.Println("Mock server running at:", mockedAwsUrl)

	tests.SetTestEnv(t, "AWS_ENDPOINT_URL_STS", mockedAwsUrl)
	tests.SetTestEnv(t, "AWS_ENDPOINT_URL", mockedAwsUrl)

	configToml := `SecretName = "ptr1/quorum/nodekey"
SecretVersion = "f368ae7f-41e6-4d25-8e8e-a3aad0130846"
KmsKeyId = "alias/mykey"`

	fmt.Printf("Using config: %s\n", configToml)

	client, err := NewAwsClient([]byte(configToml))

	require.NotNil(t, client, "client should be nil")
	require.Nil(t, err, "Error should be nil")

	responseData, err := client.SecretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:  aws.String("ptr1/quorum/nodekey"),
		VersionId: aws.String("f368ae7f-41e6-4d25-8e8e-a3aad0130846"),
	})

	fmt.Printf("Error Message: %v\n", err)
	fmt.Printf("Response Message: %v\n", tests.ToJsonString(responseData))
	require.Nil(t, err, "Failed to retrieve secret")
	require.Equal(t, "7e7660504f5234b94c6bf873e04f8a650afeef8a0afed18c45d598017c47225d", *responseData.SecretString)
}

func setupMockAwsEnvironmentUsingWebToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "mocked-aws-token.jwt")

	fakeToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215Lm9pZGMucHJvdmlkZXIiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiZHVtbXktYXVkaWVuY2UiLCJleHAiOjQ3OTk5OTk5OTksImlhdCI6MTYwOTAwMDAwMH0.dummysignature"
	if err := os.WriteFile(tokenFile, []byte(fakeToken), 0o644); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	os.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	os.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/my-test-role")
	os.Setenv("AWS_REGION", "us-east-1")
}
