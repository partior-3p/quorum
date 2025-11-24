package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func SetTestEnv(t *testing.T, key string, value string) {
	originalValue, exist := os.LookupEnv(key)
	err := os.Setenv(key, value)
	if err != nil {
		t.Fatalf("Failed to set env variable: %s", key)
	}

	t.Cleanup(func() {
		if exist {
			os.Setenv(key, originalValue)
		} else {
			os.Unsetenv(key)
		}
	})
}

func UnsetTestEnv(t *testing.T, key string) {
	originalValue, exist := os.LookupEnv(key)
	err := os.Unsetenv(key)
	if err != nil {
		t.Fatalf("Failed to unset env variable: %s", key)
	}

	t.Cleanup(func() {
		if exist {
			os.Setenv(key, originalValue)
		}
	})
}

func SetupMockAwsEnvironmentUsingWebToken(t *testing.T, mockedAwsEndpointUrl string) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "mocked-aws-token.jwt")

	fakeToken, _ := GenerateFakeAWSJWT()
	if err := os.WriteFile(tokenFile, []byte(fakeToken), 0o644); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	SetTestEnv(t, "AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	SetTestEnv(t, "AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/my-test-role")
	SetTestEnv(t, "AWS_REGION", "us-east-1")
}

func GenerateFakeAWSJWT() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "system:serviceaccount:default:my-service-account",
		"iss": "https://mock-issuer.example.com",
		"aud": "localhost",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}
