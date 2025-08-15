package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	config := HTTPClientConfig{
		Timeout:    10 * time.Second,
		MaxRetries: 5,
		UserAgent:  "test-agent",
	}

	client := NewHTTPClient(config)
	
	assert.NotNil(t, client)
	assert.Equal(t, config.Timeout, client.config.Timeout)
	assert.Equal(t, config.MaxRetries, client.config.MaxRetries)
	assert.Equal(t, config.UserAgent, client.config.UserAgent)
}

func TestNewDefaultHTTPClient(t *testing.T) {
	client := NewDefaultHTTPClient()
	
	assert.NotNil(t, client)
	assert.Equal(t, 30*time.Second, client.config.Timeout)
	assert.Equal(t, 3, client.config.MaxRetries)
	assert.Equal(t, "raven-betanet-dual-cli/1.0", client.config.UserAgent)
}

func TestHTTPClient_Get(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Greater(t, resp.Duration, time.Duration(0))
	assert.Equal(t, 1, resp.Attempt)
}

func TestHTTPClient_GetWithContext(t *testing.T) {
	// Create test server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	// Test with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.GetWithContext(ctx, server.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestHTTPClient_Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	config := HTTPClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		RetryDelay: 10 * time.Millisecond,
	}
	client := NewHTTPClient(config)

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 3, resp.Attempt)
	assert.Equal(t, 3, attempts)
}

func TestHTTPClient_ShouldRetry(t *testing.T) {
	client := NewDefaultHTTPClient()

	tests := []struct {
		statusCode int
		shouldRetry bool
	}{
		{http.StatusOK, false},
		{http.StatusNotFound, false},
		{http.StatusBadRequest, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			result := client.shouldRetry(tt.statusCode)
			assert.Equal(t, tt.shouldRetry, result)
		})
	}
}

func TestHTTPClient_GetJSON(t *testing.T) {
	// Test data
	testData := map[string]interface{}{
		"name":    "test",
		"version": "1.0.0",
		"active":  true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"test","version":"1.0.0","active":true}`))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	var result map[string]interface{}
	err := client.GetJSON(server.URL, &result)
	require.NoError(t, err)

	assert.Equal(t, testData["name"], result["name"])
	assert.Equal(t, testData["version"], result["version"])
	assert.Equal(t, testData["active"], result["active"])
}

func TestHTTPClient_GetJSON_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid json`))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	var result map[string]interface{}
	err := client.GetJSON(server.URL, &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal JSON response")
}

func TestHTTPClient_PostJSON(t *testing.T) {
	requestData := map[string]interface{}{
		"name": "test-request",
		"id":   123,
	}

	responseData := map[string]interface{}{
		"status": "success",
		"id":     123,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","id":123}`))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	var result map[string]interface{}
	err := client.PostJSON(server.URL, requestData, &result)
	require.NoError(t, err)

	assert.Equal(t, responseData["status"], result["status"])
	assert.Equal(t, float64(responseData["id"].(int)), result["id"]) // JSON unmarshals numbers as float64
}

func TestHTTPClient_CheckURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "HEAD", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	err := client.CheckURL(server.URL)
	assert.NoError(t, err)
}

func TestHTTPClient_CheckURL_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()
	
	err := client.CheckURL(server.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "URL not accessible")
}

func TestHTTPClient_SetTimeout(t *testing.T) {
	client := NewDefaultHTTPClient()
	originalTimeout := client.config.Timeout

	newTimeout := 60 * time.Second
	client.SetTimeout(newTimeout)

	assert.Equal(t, newTimeout, client.config.Timeout)
	assert.Equal(t, newTimeout, client.client.Timeout)
	assert.NotEqual(t, originalTimeout, client.config.Timeout)
}

func TestHTTPClient_SetMaxRetries(t *testing.T) {
	client := NewDefaultHTTPClient()
	originalMaxRetries := client.config.MaxRetries

	newMaxRetries := 10
	client.SetMaxRetries(newMaxRetries)

	assert.Equal(t, newMaxRetries, client.config.MaxRetries)
	assert.NotEqual(t, originalMaxRetries, client.config.MaxRetries)
}

func TestHTTPClient_SetUserAgent(t *testing.T) {
	client := NewDefaultHTTPClient()
	originalUserAgent := client.config.UserAgent

	newUserAgent := "custom-user-agent/2.0"
	client.SetUserAgent(newUserAgent)

	assert.Equal(t, newUserAgent, client.config.UserAgent)
	assert.NotEqual(t, originalUserAgent, client.config.UserAgent)
}

func TestHTTPClient_UserAgentHeader(t *testing.T) {
	customUserAgent := "test-user-agent/1.0"
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, customUserAgent, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HTTPClientConfig{
		UserAgent: customUserAgent,
	}
	client := NewHTTPClient(config)
	
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPClient_GetConfig(t *testing.T) {
	config := HTTPClientConfig{
		Timeout:    15 * time.Second,
		MaxRetries: 5,
		UserAgent:  "test-config",
	}

	client := NewHTTPClient(config)
	retrievedConfig := client.GetConfig()

	assert.Equal(t, config.Timeout, retrievedConfig.Timeout)
	assert.Equal(t, config.MaxRetries, retrievedConfig.MaxRetries)
	assert.Equal(t, config.UserAgent, retrievedConfig.UserAgent)
}

// Benchmark tests
func BenchmarkHTTPClient_Get(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("benchmark response"))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(server.URL)
		require.NoError(b, err)
		resp.Body.Close()
	}
}

func BenchmarkHTTPClient_GetJSON(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"benchmark","version":"1.0.0"}`))
	}))
	defer server.Close()

	client := NewDefaultHTTPClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result map[string]interface{}
		err := client.GetJSON(server.URL, &result)
		require.NoError(b, err)
	}
}