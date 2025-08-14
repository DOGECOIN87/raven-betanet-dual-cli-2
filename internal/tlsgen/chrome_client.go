package tlsgen

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/raven-betanet/dual-cli/internal/utils"
)

const (
	ChromeAPIEndpoint = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Linux"
	DefaultTimeout    = 30 * time.Second
)

// ChromeRelease represents a Chrome release from the API
type ChromeRelease struct {
	Version   string    `json:"version"`
	Channel   string    `json:"channel"`
	Platform  string    `json:"platform"`
	Timestamp int64     `json:"timestamp"`
	Date      time.Time `json:"-"`
}

// ChromeClient handles fetching Chrome version information
type ChromeClient struct {
	httpClient *utils.HTTPClient
	apiURL     string
}

// NewChromeClient creates a new Chrome API client
func NewChromeClient() *ChromeClient {
	return &ChromeClient{
		httpClient: utils.NewHTTPClient(utils.HTTPClientConfig{
			Timeout: DefaultTimeout,
		}),
		apiURL: ChromeAPIEndpoint,
	}
}

// NewChromeClientWithURL creates a Chrome client with custom API URL
func NewChromeClientWithURL(apiURL string) *ChromeClient {
	return &ChromeClient{
		httpClient: utils.NewHTTPClient(utils.HTTPClientConfig{
			Timeout: DefaultTimeout,
		}),
		apiURL: apiURL,
	}
}

// FetchLatestVersions fetches the latest Chrome stable versions
func (c *ChromeClient) FetchLatestVersions() ([]ChromeVersion, error) {
	resp, err := c.httpClient.Get(c.apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Chrome releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Chrome API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var releases []ChromeRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("failed to parse Chrome releases: %w", err)
	}

	return c.convertToVersions(releases)
}

// FetchLatestVersion fetches the single latest Chrome stable version
func (c *ChromeClient) FetchLatestVersion() (*ChromeVersion, error) {
	versions, err := c.FetchLatestVersions()
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no Chrome versions found")
	}

	// Return the newest version (first in sorted list)
	return &versions[0], nil
}

// FetchStableVersions fetches the current stable (N) and previous stable (N-2) versions
func (c *ChromeClient) FetchStableVersions() (*ChromeVersion, *ChromeVersion, error) {
	versions, err := c.FetchLatestVersions()
	if err != nil {
		return nil, nil, err
	}

	if len(versions) < 2 {
		return nil, nil, fmt.Errorf("insufficient Chrome versions found, need at least 2")
	}

	// Return current stable (N) and N-2 version
	current := &versions[0]
	var previous *ChromeVersion
	
	// Find N-2 version (skip N-1, get N-2)
	if len(versions) >= 3 {
		previous = &versions[2]
	} else {
		previous = &versions[1]
	}

	return current, previous, nil
}

// convertToVersions converts Chrome releases to ChromeVersion structs and sorts them
func (c *ChromeClient) convertToVersions(releases []ChromeRelease) ([]ChromeVersion, error) {
	var versions []ChromeVersion

	for _, release := range releases {
		version, err := ParseVersion(release.Version)
		if err != nil {
			// Skip invalid versions rather than failing completely
			continue
		}

		version.Channel = release.Channel
		version.Platform = release.Platform
		version.Date = time.Unix(release.Timestamp, 0)

		versions = append(versions, *version)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no valid Chrome versions found")
	}

	// Sort versions by newest first
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].IsNewer(versions[j])
	})

	return versions, nil
}