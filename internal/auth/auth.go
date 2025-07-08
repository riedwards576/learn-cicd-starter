package auth

import (
	"net/http"
	"testing"
)

//Below tests check for
// 1. Success case: Proper header with "ApiKey" prefix.
// 2. Missing header: No Authorization header at all.
// 3. Malformed header: Wrong scheme like "Bearer" or missing key.

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if apiKey != "my-secret-key" {
		t.Errorf("expected 'my-secret-key', got '%s'", apiKey)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer sometoken")

	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
}
