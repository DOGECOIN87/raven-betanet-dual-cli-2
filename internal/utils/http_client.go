package utils

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"time"
)

// HTTPClient wraps http.Client with retry logic and exponential backoff
type HTTPClient struct {
	client      *http.Client
	retryCount  int
	backoffFunc func(int) time.Duration
	logger      *Logger
}

// HTTPClientConfig holds configuration for the HTTP client
type HTTPClientConfig struct {
	Timeout     time.Duration
	RetryCount  int
	BackoffFunc func(int) time.Duration
	Logger      *Logger
}

// NewHTTPClient creates a new HTTP client with retry logic
func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.BackoffFunc == nil {
		config.BackoffFunc = ExponentialBackoff
	}
	if config.Logger == nil {
		config.Logger = NewDefaultLogger()
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		retryCount:  config.RetryCount,
		backoffFunc: config.BackoffFunc,
		logger:      config.Logger,
	}
}

// NewDefaultHTTPClient creates an HTTP client with default configuration
func NewDefaultHTTPClient() *HTTPClient {
	return NewHTTPClient(HTTPClientConfig{})
}

// Get performs a GET request with retry logic
func (h *HTTPClient) Get(url string) (*http.Response, error) {
	return h.GetWithContext(context.Background(), url)
}

// GetWithContext performs a GET request with retry logic and context
func (h *HTTPClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	return h.DoWithRetry(req)
}

// Post performs a POST request with retry logic
func (h *HTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return h.PostWithContext(context.Background(), url, contentType, body)
}

// PostWithContext performs a POST request with retry logic and context
func (h *HTTPClient) PostWithContext(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return h.DoWithRetry(req)
}

// DoWithRetry executes an HTTP request with retry logic
func (h *HTTPClient) DoWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt <= h.retryCount; attempt++ {
		// Clone the request for each attempt (in case body needs to be re-read)
		reqClone := req.Clone(req.Context())
		
		h.logger.WithContext(map[string]interface{}{
			"url":     req.URL.String(),
			"method":  req.Method,
			"attempt": attempt + 1,
			"max_attempts": h.retryCount + 1,
		}).Debug("Making HTTP request")
		
		resp, err := h.client.Do(reqClone)
		if err != nil {
			lastErr = err
			if attempt < h.retryCount && h.shouldRetry(err, nil) {
				backoff := h.backoffFunc(attempt)
				h.logger.WithContext(map[string]interface{}{
					"error":    err.Error(),
					"backoff":  backoff.String(),
					"attempt":  attempt + 1,
				}).Warn("HTTP request failed, retrying")
				
				select {
				case <-time.After(backoff):
					continue
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			}
			continue
		}
		
		// Check if we should retry based on status code
		if h.shouldRetry(nil, resp) {
			if attempt < h.retryCount {
				resp.Body.Close() // Close the response body before retrying
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
				
				backoff := h.backoffFunc(attempt)
				h.logger.WithContext(map[string]interface{}{
					"status_code": resp.StatusCode,
					"status":      resp.Status,
					"backoff":     backoff.String(),
					"attempt":     attempt + 1,
				}).Warn("HTTP request returned retryable status, retrying")
				
				select {
				case <-time.After(backoff):
					continue
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			} else {
				// Exhausted retries with retryable status
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
				continue
			}
		}
		
		// Success or non-retryable error
		if resp.StatusCode >= 400 {
			h.logger.WithContext(map[string]interface{}{
				"status_code": resp.StatusCode,
				"status":      resp.Status,
			}).Error("HTTP request failed with non-retryable status")
		} else {
			h.logger.WithContext(map[string]interface{}{
				"status_code": resp.StatusCode,
				"status":      resp.Status,
			}).Debug("HTTP request successful")
		}
		
		return resp, nil
	}
	
	return nil, fmt.Errorf("HTTP request failed after %d attempts: %w", h.retryCount+1, lastErr)
}

// shouldRetry determines if a request should be retried based on error or response
func (h *HTTPClient) shouldRetry(err error, resp *http.Response) bool {
	// Retry on network errors
	if err != nil {
		return true
	}
	
	// Retry on specific HTTP status codes
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusTooManyRequests,     // 429
			 http.StatusInternalServerError,  // 500
			 http.StatusBadGateway,          // 502
			 http.StatusServiceUnavailable,  // 503
			 http.StatusGatewayTimeout:      // 504
			return true
		}
	}
	
	return false
}

// ExponentialBackoff implements exponential backoff with jitter
func ExponentialBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	
	// Base delay of 1 second, exponentially increasing
	delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	
	// Cap at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	
	// Add jitter (±25% of delay)
	jitter := time.Duration(float64(delay) * 0.25)
	delay = delay + time.Duration(float64(jitter)*(2*rand.Float64()-1))
	
	if delay < 0 {
		delay = time.Second
	}
	
	// Ensure we don't exceed the cap after jitter
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	
	return delay
}

// LinearBackoff implements linear backoff
func LinearBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	return time.Duration(attempt+1) * time.Second
}

// FixedBackoff implements fixed delay backoff
func FixedBackoff(delay time.Duration) func(int) time.Duration {
	return func(attempt int) time.Duration {
		return delay
	}
}