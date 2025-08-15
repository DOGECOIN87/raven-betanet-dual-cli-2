package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HTTPClientConfig holds configuration for the HTTP client
type HTTPClientConfig struct {
	Timeout         time.Duration `yaml:"timeout" env:"HTTP_TIMEOUT"`
	MaxRetries      int           `yaml:"max_retries" env:"HTTP_MAX_RETRIES"`
	RetryDelay      time.Duration `yaml:"retry_delay" env:"HTTP_RETRY_DELAY"`
	UserAgent       string        `yaml:"user_agent" env:"HTTP_USER_AGENT"`
	FollowRedirects bool          `yaml:"follow_redirects" env:"HTTP_FOLLOW_REDIRECTS"`
}

// HTTPClient wraps http.Client with additional functionality
type HTTPClient struct {
	client *http.Client
	config HTTPClientConfig
	logger *Logger
}

// HTTPResponse represents an HTTP response with additional metadata
type HTTPResponse struct {
	*http.Response
	Duration time.Duration
	Attempt  int
}

// NewHTTPClient creates a new HTTP client with the given configuration
func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "raven-betanet-dual-cli/1.0"
	}
	if !config.FollowRedirects {
		config.FollowRedirects = true
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: config.Timeout,
	}

	// Configure redirect policy
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &HTTPClient{
		client: client,
		config: config,
		logger: NewDefaultLogger(),
	}
}

// NewDefaultHTTPClient creates an HTTP client with default configuration
func NewDefaultHTTPClient() *HTTPClient {
	return NewHTTPClient(HTTPClientConfig{})
}

// SetLogger sets the logger for the HTTP client
func (h *HTTPClient) SetLogger(logger *Logger) {
	h.logger = logger
}

// Get performs a GET request with retry logic
func (h *HTTPClient) Get(url string) (*HTTPResponse, error) {
	return h.GetWithContext(context.Background(), url)
}

// GetWithContext performs a GET request with context and retry logic
func (h *HTTPClient) GetWithContext(ctx context.Context, url string) (*HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return h.Do(req)
}

// Post performs a POST request with retry logic
func (h *HTTPClient) Post(url, contentType string, body io.Reader) (*HTTPResponse, error) {
	return h.PostWithContext(context.Background(), url, contentType, body)
}

// PostWithContext performs a POST request with context and retry logic
func (h *HTTPClient) PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return h.Do(req)
}

// Do executes an HTTP request with retry logic
func (h *HTTPClient) Do(req *http.Request) (*HTTPResponse, error) {
	return h.DoWithRetry(req, h.config.MaxRetries)
}

// DoWithRetry executes an HTTP request with custom retry count
func (h *HTTPClient) DoWithRetry(req *http.Request, maxRetries int) (*HTTPResponse, error) {
	// Set User-Agent header
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", h.config.UserAgent)
	}

	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		start := time.Now()
		
		// Clone request for retry attempts
		reqClone := h.cloneRequest(req)
		
		h.logger.WithComponent("http-client").Debugf("Attempting request to %s (attempt %d/%d)", req.URL.String(), attempt+1, maxRetries+1)
		
		resp, err := h.client.Do(reqClone)
		duration := time.Since(start)
		
		if err != nil {
			lastErr = err
			h.logger.WithComponent("http-client").Warnf("Request failed (attempt %d/%d): %v", attempt+1, maxRetries+1, err)
			
			// Don't retry on context cancellation
			if req.Context().Err() != nil {
				return nil, fmt.Errorf("request cancelled: %w", err)
			}
			
			// Wait before retry (except on last attempt)
			if attempt < maxRetries {
				h.waitForRetry(attempt)
			}
			continue
		}

		// Check if we should retry based on status code
		if h.shouldRetry(resp.StatusCode) && attempt < maxRetries {
			resp.Body.Close()
			h.logger.WithComponent("http-client").Warnf("Request returned %d, retrying (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries+1)
			h.waitForRetry(attempt)
			continue
		}

		// Success or non-retryable error
		h.logger.WithComponent("http-client").Debugf("Request completed: %s %d in %v", req.URL.String(), resp.StatusCode, duration)
		
		return &HTTPResponse{
			Response: resp,
			Duration: duration,
			Attempt:  attempt + 1,
		}, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
}

// cloneRequest creates a copy of an HTTP request
func (h *HTTPClient) cloneRequest(req *http.Request) *http.Request {
	reqClone := req.Clone(req.Context())
	
	// Clone headers
	reqClone.Header = make(http.Header)
	for key, values := range req.Header {
		reqClone.Header[key] = append([]string(nil), values...)
	}
	
	return reqClone
}

// shouldRetry determines if a request should be retried based on status code
func (h *HTTPClient) shouldRetry(statusCode int) bool {
	// Retry on server errors and some client errors
	switch statusCode {
	case http.StatusTooManyRequests,     // 429
		 http.StatusInternalServerError,  // 500
		 http.StatusBadGateway,          // 502
		 http.StatusServiceUnavailable,  // 503
		 http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// waitForRetry waits before retrying a request with exponential backoff
func (h *HTTPClient) waitForRetry(attempt int) {
	// Exponential backoff: delay * (2^attempt)
	delay := h.config.RetryDelay * time.Duration(1<<uint(attempt))
	
	// Cap the delay at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	
	h.logger.WithComponent("http-client").Debugf("Waiting %v before retry", delay)
	time.Sleep(delay)
}

// GetJSON performs a GET request and unmarshals JSON response
func (h *HTTPClient) GetJSON(url string, target interface{}) error {
	return h.GetJSONWithContext(context.Background(), url, target)
}

// GetJSONWithContext performs a GET request with context and unmarshals JSON response
func (h *HTTPClient) GetJSONWithContext(ctx context.Context, url string, target interface{}) error {
	resp, err := h.GetWithContext(ctx, url)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		h.logger.WithComponent("http-client").Warnf("Expected JSON content type, got: %s", contentType)
	}

	// Read and unmarshal response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return nil
}

// PostJSON performs a POST request with JSON body and unmarshals JSON response
func (h *HTTPClient) PostJSON(url string, requestBody, responseBody interface{}) error {
	return h.PostJSONWithContext(context.Background(), url, requestBody, responseBody)
}

// PostJSONWithContext performs a POST request with context, JSON body and unmarshals JSON response
func (h *HTTPClient) PostJSONWithContext(ctx context.Context, url string, requestBody, responseBody interface{}) error {
	// Marshal request body
	var body io.Reader
	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		body = strings.NewReader(string(jsonData))
	}

	resp, err := h.PostWithContext(ctx, url, "application/json", body)
	if err != nil {
		return fmt.Errorf("POST request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// If no response body expected, return early
	if responseBody == nil {
		return nil
	}

	// Read and unmarshal response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if err := json.Unmarshal(respData, responseBody); err != nil {
		return fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return nil
}

// DownloadFile downloads a file from the given URL
func (h *HTTPClient) DownloadFile(url, filepath string) error {
	return h.DownloadFileWithContext(context.Background(), url, filepath)
}

// DownloadFileWithContext downloads a file from the given URL with context
func (h *HTTPClient) DownloadFileWithContext(ctx context.Context, url, filepath string) error {
	resp, err := h.GetWithContext(ctx, url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Create the file
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy response body to file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	h.logger.WithComponent("http-client").Infof("Downloaded file: %s -> %s", url, filepath)
	return nil
}

// CheckURL checks if a URL is accessible (HEAD request)
func (h *HTTPClient) CheckURL(url string) error {
	return h.CheckURLWithContext(context.Background(), url)
}

// CheckURLWithContext checks if a URL is accessible with context (HEAD request)
func (h *HTTPClient) CheckURLWithContext(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HEAD request: %w", err)
	}

	resp, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("URL not accessible: HTTP %d", resp.StatusCode)
	}

	return nil
}

// GetConfig returns the HTTP client configuration
func (h *HTTPClient) GetConfig() HTTPClientConfig {
	return h.config
}

// SetTimeout updates the client timeout
func (h *HTTPClient) SetTimeout(timeout time.Duration) {
	h.config.Timeout = timeout
	h.client.Timeout = timeout
}

// SetMaxRetries updates the maximum retry count
func (h *HTTPClient) SetMaxRetries(maxRetries int) {
	h.config.MaxRetries = maxRetries
}

// SetUserAgent updates the User-Agent header
func (h *HTTPClient) SetUserAgent(userAgent string) {
	h.config.UserAgent = userAgent
}

// SetClient sets the underlying HTTP client (for compatibility with tests)
func (c *HTTPClient) SetClient(client *http.Client) {
	c.client = client
}