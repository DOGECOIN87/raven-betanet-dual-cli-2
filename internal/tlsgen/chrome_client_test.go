package tlsgen

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewChromeClient(t *testing.T) {
	client := NewChromeClient()
	
	if client == nil {
		t.Fatal("NewChromeClient() returned nil")
	}
	
	if client.apiURL != ChromeAPIEndpoint {
		t.Errorf("NewChromeClient() apiURL = %v, want %v", client.apiURL, ChromeAPIEndpoint)
	}
	
	if client.httpClient == nil {
		t.Error("NewChromeClient() httpClient is nil")
	}
}

func TestNewChromeClientWithURL(t *testing.T) {
	customURL := "https://example.com/api"
	client := NewChromeClientWithURL(customURL)
	
	if client == nil {
		t.Fatal("NewChromeClientWithURL() returned nil")
	}
	
	if client.apiURL != customURL {
		t.Errorf("NewChromeClientWithURL() apiURL = %v, want %v", client.apiURL, customURL)
	}
}

func TestChromeClient_FetchLatestVersions(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		statusCode     int
		expectedCount  int
		expectError    bool
	}{
		{
			name: "successful response with multiple versions",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				},
				{
					"version": "119.0.6045.199",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1700234567
				},
				{
					"version": "118.0.5993.117",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1699234567
				}
			]`,
			statusCode:    200,
			expectedCount: 3,
			expectError:   false,
		},
		{
			name: "successful response with single version",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				}
			]`,
			statusCode:    200,
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:           "empty response",
			serverResponse: `[]`,
			statusCode:     200,
			expectedCount:  0,
			expectError:    true, // Should error when no valid versions found
		},
		{
			name: "response with invalid version format",
			serverResponse: `[
				{
					"version": "invalid.version",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				}
			]`,
			statusCode:    200,
			expectedCount: 0,
			expectError:   true,
		},
		{
			name: "mixed valid and invalid versions",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				},
				{
					"version": "invalid.version",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1700234567
				}
			]`,
			statusCode:    200,
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:           "server error",
			serverResponse: `{"error": "Internal server error"}`,
			statusCode:     500,
			expectedCount:  0,
			expectError:    true,
		},
		{
			name:           "invalid JSON response",
			serverResponse: `invalid json`,
			statusCode:     200,
			expectedCount:  0,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			// Create client with test server URL
			client := NewChromeClientWithURL(server.URL)
			
			// Test the method
			versions, err := client.FetchLatestVersions()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("FetchLatestVersions() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("FetchLatestVersions() unexpected error: %v", err)
				return
			}
			
			if len(versions) != tt.expectedCount {
				t.Errorf("FetchLatestVersions() returned %d versions, want %d", len(versions), tt.expectedCount)
			}
			
			// Verify versions are sorted (newest first)
			for i := 1; i < len(versions); i++ {
				if versions[i].IsNewer(versions[i-1]) {
					t.Errorf("FetchLatestVersions() versions not sorted correctly: %v should be older than %v", 
						versions[i], versions[i-1])
				}
			}
		})
	}
}

func TestChromeClient_FetchLatestVersion(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		statusCode     int
		expectedVersion string
		expectError    bool
	}{
		{
			name: "successful response",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				},
				{
					"version": "119.0.6045.199",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1700234567
				}
			]`,
			statusCode:      200,
			expectedVersion: "120.0.6099.109",
			expectError:     false,
		},
		{
			name:           "empty response",
			serverResponse: `[]`,
			statusCode:     200,
			expectError:    true,
		},
		{
			name:           "server error",
			serverResponse: `{"error": "Internal server error"}`,
			statusCode:     500,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			// Create client with test server URL
			client := NewChromeClientWithURL(server.URL)
			
			// Test the method
			version, err := client.FetchLatestVersion()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("FetchLatestVersion() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("FetchLatestVersion() unexpected error: %v", err)
				return
			}
			
			if version == nil {
				t.Errorf("FetchLatestVersion() returned nil version")
				return
			}
			
			if version.String() != tt.expectedVersion {
				t.Errorf("FetchLatestVersion() returned version %v, want %v", version.String(), tt.expectedVersion)
			}
		})
	}
}

func TestChromeClient_FetchStableVersions(t *testing.T) {
	tests := []struct {
		name              string
		serverResponse    string
		statusCode        int
		expectedCurrent   string
		expectedPrevious  string
		expectError       bool
	}{
		{
			name: "successful response with 3+ versions",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				},
				{
					"version": "119.0.6045.199",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1700234567
				},
				{
					"version": "118.0.5993.117",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1699234567
				}
			]`,
			statusCode:       200,
			expectedCurrent:  "120.0.6099.109",
			expectedPrevious: "118.0.5993.117", // N-2 version
			expectError:      false,
		},
		{
			name: "successful response with exactly 2 versions",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				},
				{
					"version": "119.0.6045.199",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1700234567
				}
			]`,
			statusCode:       200,
			expectedCurrent:  "120.0.6099.109",
			expectedPrevious: "119.0.6045.199", // Falls back to N-1 when N-2 not available
			expectError:      false,
		},
		{
			name: "insufficient versions",
			serverResponse: `[
				{
					"version": "120.0.6099.109",
					"channel": "Stable",
					"platform": "Linux",
					"timestamp": 1701234567
				}
			]`,
			statusCode:  200,
			expectError: true,
		},
		{
			name:           "empty response",
			serverResponse: `[]`,
			statusCode:     200,
			expectError:    true,
		},
		{
			name:           "server error",
			serverResponse: `{"error": "Internal server error"}`,
			statusCode:     500,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			// Create client with test server URL
			client := NewChromeClientWithURL(server.URL)
			
			// Test the method
			current, previous, err := client.FetchStableVersions()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("FetchStableVersions() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("FetchStableVersions() unexpected error: %v", err)
				return
			}
			
			if current == nil {
				t.Errorf("FetchStableVersions() returned nil current version")
				return
			}
			
			if previous == nil {
				t.Errorf("FetchStableVersions() returned nil previous version")
				return
			}
			
			if current.String() != tt.expectedCurrent {
				t.Errorf("FetchStableVersions() current version = %v, want %v", current.String(), tt.expectedCurrent)
			}
			
			if previous.String() != tt.expectedPrevious {
				t.Errorf("FetchStableVersions() previous version = %v, want %v", previous.String(), tt.expectedPrevious)
			}
			
			// Verify current is newer than previous
			if !current.IsNewer(*previous) {
				t.Errorf("FetchStableVersions() current version %v should be newer than previous %v", 
					current.String(), previous.String())
			}
		})
	}
}

func TestChromeClient_convertToVersions(t *testing.T) {
	client := NewChromeClient()
	
	tests := []struct {
		name          string
		releases      []ChromeRelease
		expectedCount int
		expectError   bool
	}{
		{
			name: "valid releases",
			releases: []ChromeRelease{
				{
					Version:   "120.0.6099.109",
					Channel:   "Stable",
					Platform:  "Linux",
					Timestamp: 1701234567,
				},
				{
					Version:   "119.0.6045.199",
					Channel:   "Stable",
					Platform:  "Linux",
					Timestamp: 1700234567,
				},
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "mixed valid and invalid releases",
			releases: []ChromeRelease{
				{
					Version:   "120.0.6099.109",
					Channel:   "Stable",
					Platform:  "Linux",
					Timestamp: 1701234567,
				},
				{
					Version:   "invalid.version",
					Channel:   "Stable",
					Platform:  "Linux",
					Timestamp: 1700234567,
				},
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "all invalid releases",
			releases: []ChromeRelease{
				{
					Version:   "invalid.version",
					Channel:   "Stable",
					Platform:  "Linux",
					Timestamp: 1701234567,
				},
			},
			expectedCount: 0,
			expectError:   true,
		},
		{
			name:          "empty releases",
			releases:      []ChromeRelease{},
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versions, err := client.convertToVersions(tt.releases)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("convertToVersions() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("convertToVersions() unexpected error: %v", err)
				return
			}
			
			if len(versions) != tt.expectedCount {
				t.Errorf("convertToVersions() returned %d versions, want %d", len(versions), tt.expectedCount)
			}
			
			// Verify versions are sorted (newest first)
			for i := 1; i < len(versions); i++ {
				if versions[i].IsNewer(versions[i-1]) {
					t.Errorf("convertToVersions() versions not sorted correctly: %v should be older than %v", 
						versions[i], versions[i-1])
				}
			}
			
			// Verify metadata is set correctly
			for i, version := range versions {
				if version.Channel != tt.releases[i].Channel {
					t.Errorf("convertToVersions() version[%d] channel = %v, want %v", 
						i, version.Channel, tt.releases[i].Channel)
				}
				if version.Platform != tt.releases[i].Platform {
					t.Errorf("convertToVersions() version[%d] platform = %v, want %v", 
						i, version.Platform, tt.releases[i].Platform)
				}
				expectedDate := time.Unix(tt.releases[i].Timestamp, 0)
				if !version.Date.Equal(expectedDate) {
					t.Errorf("convertToVersions() version[%d] date = %v, want %v", 
						i, version.Date, expectedDate)
				}
			}
		})
	}
}