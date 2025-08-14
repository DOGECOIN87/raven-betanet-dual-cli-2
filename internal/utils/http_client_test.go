package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClient(t *testing.T) {
	config := HTTPClientConfig{
		Timeout:    10 * time.Second,
		RetryCount: 5,
	}
	
	client := NewHTTPClient(config)
	
	if client == nil {
		t.Fatal("NewHTTPClient() returned nil")
	}
	if client.client.Timeout != 10*time.Second {
		t.Errorf("Expected timeout=10s, got: %v", client.client.Timeout)
	}
	if client.retryCount != 5 {
		t.Errorf("Expected retryCount=5, got: %d", client.retryCount)
	}
}

func TestNewHTTPClientDefaults(t *testing.T) {
	client := NewHTTPClient(HTTPClientConfig{})
	
	if client.client.Timeout != 30*time.Second {
		t.Errorf("Expected default timeout=30s, got: %v", client.client.Timeout)
	}
	if client.retryCount != 3 {
		t.Errorf("Expected default retryCount=3, got: %d", client.retryCount)
	}
	if client.backoffFunc == nil {
		t.Error("Expected default backoffFunc to be set")
	}
	if client.logger == nil {
		t.Error("Expected default logger to be set")
	}
}

func TestNewDefaultHTTPClient(t *testing.T) {
	client := NewDefaultHTTPClient()
	
	if client == nil {
		t.Fatal("NewDefaultHTTPClient() returned nil")
	}
	if client.client.Timeout != 30*time.Second {
		t.Errorf("Expected default timeout=30s, got: %v", client.client.Timeout)
	}
}

func TestHTTPClient_GetSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got: %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()
	
	client := NewDefaultHTTPClient()
	resp, err := client.Get(server.URL)
	
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(body) != "success" {
		t.Errorf("Expected body 'success', got: %s", string(body))
	}
}

func TestHTTPClient_PostSuccess(t *testing.T) {
	expectedBody := "test data"
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got: %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got: %s", r.Header.Get("Content-Type"))
		}
		
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		if string(body) != expectedBody {
			t.Errorf("Expected request body '%s', got: %s", expectedBody, string(body))
		}
		
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer server.Close()
	
	client := NewDefaultHTTPClient()
	resp, err := client.Post(server.URL, "application/json", strings.NewReader(expectedBody))
	
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got: %d", resp.StatusCode)
	}
}

func TestHTTPClient_RetryOnServerError(t *testing.T) {
	attemptCount := 0
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success after retry"))
	}))
	defer server.Close()
	
	// Use a faster backoff for testing
	client := NewHTTPClient(HTTPClientConfig{
		RetryCount:  3,
		BackoffFunc: FixedBackoff(10 * time.Millisecond),
	})
	
	resp, err := client.Get(server.URL)
	
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", resp.StatusCode)
	}
	if attemptCount != 3 {
		t.Errorf("Expected 3 attempts, got: %d", attemptCount)
	}
}

func TestHTTPClient_RetryExhaustion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	client := NewHTTPClient(HTTPClientConfig{
		RetryCount:  2,
		BackoffFunc: FixedBackoff(1 * time.Millisecond),
	})
	
	resp, err := client.Get(server.URL)
	
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected error after retry exhaustion, got nil")
	}
	if !strings.Contains(err.Error(), "failed after 3 attempts") {
		t.Errorf("Expected error message about attempts, got: %s", err.Error())
	}
}

func TestHTTPClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay to allow context cancellation
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	client := NewDefaultHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	resp, err := client.GetWithContext(ctx, server.URL)
	
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected context cancellation error, got nil")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestHTTPClient_ShouldRetry(t *testing.T) {
	client := NewDefaultHTTPClient()
	
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{
			name: "network error",
			err:  fmt.Errorf("network error"),
			want: true,
		},
		{
			name:       "429 Too Many Requests",
			statusCode: http.StatusTooManyRequests,
			want:       true,
		},
		{
			name:       "500 Internal Server Error",
			statusCode: http.StatusInternalServerError,
			want:       true,
		},
		{
			name:       "502 Bad Gateway",
			statusCode: http.StatusBadGateway,
			want:       true,
		},
		{
			name:       "503 Service Unavailable",
			statusCode: http.StatusServiceUnavailable,
			want:       true,
		},
		{
			name:       "504 Gateway Timeout",
			statusCode: http.StatusGatewayTimeout,
			want:       true,
		},
		{
			name:       "400 Bad Request",
			statusCode: http.StatusBadRequest,
			want:       false,
		},
		{
			name:       "404 Not Found",
			statusCode: http.StatusNotFound,
			want:       false,
		},
		{
			name:       "200 OK",
			statusCode: http.StatusOK,
			want:       false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			if tt.statusCode != 0 {
				resp = &http.Response{StatusCode: tt.statusCode}
			}
			
			got := client.shouldRetry(tt.err, resp)
			if got != tt.want {
				t.Errorf("shouldRetry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExponentialBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{0, 500*time.Millisecond, 1500*time.Millisecond}, // 1s ± 25%
		{1, 1500*time.Millisecond, 2500*time.Millisecond}, // 2s ± 25%
		{2, 3*time.Second, 5*time.Second},                 // 4s ± 25%
		{10, 22*time.Second, 30*time.Second},              // Capped at 30s
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := ExponentialBackoff(tt.attempt)
			if delay < tt.min || delay > tt.max {
				t.Errorf("ExponentialBackoff(%d) = %v, want between %v and %v", 
					tt.attempt, delay, tt.min, tt.max)
			}
		})
	}
}

func TestLinearBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 3 * time.Second},
		{5, 6 * time.Second},
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			got := LinearBackoff(tt.attempt)
			if got != tt.want {
				t.Errorf("LinearBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
			}
		})
	}
}

func TestFixedBackoff(t *testing.T) {
	delay := 5 * time.Second
	backoffFunc := FixedBackoff(delay)
	
	for attempt := 0; attempt < 5; attempt++ {
		got := backoffFunc(attempt)
		if got != delay {
			t.Errorf("FixedBackoff(%d) = %v, want %v", attempt, got, delay)
		}
	}
}

func TestHTTPClient_WithCustomLogger(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: &logBuffer,
	})
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	client := NewHTTPClient(HTTPClientConfig{
		Logger: logger,
	})
	
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	
	// Check that debug logs were written
	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "Making HTTP request") {
		t.Error("Expected debug log 'Making HTTP request' not found")
	}
	if !strings.Contains(logOutput, "HTTP request successful") {
		t.Error("Expected debug log 'HTTP request successful' not found")
	}
}