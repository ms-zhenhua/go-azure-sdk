package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"golang.org/x/oauth2"
)

// Copyright (c) HashiCorp Inc. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ManagedIdentityAuthorizerOptions struct {
	// Api describes the Azure API being used
	Api environments.Api

	// ClientId is the client ID used when authenticating
	ClientId string

	// CustomManagedIdentityEndpoint is an optional endpoint from which to obtain an access
	// token. When blank, the default is used.
	CustomManagedIdentityEndpoint string
}

// NewManagedIdentityAuthorizer returns an authorizer using a Managed Identity for authentication.
func NewManagedIdentityAuthorizer(ctx context.Context, options ManagedIdentityAuthorizerOptions) (Authorizer, error) {
	resource, err := environments.Resource(options.Api)
	if err != nil {
		return nil, fmt.Errorf("determining resource for api %q: %+v", options.Api.Name(), err)
	}
	conf, err := newManagedIdentityConfig(*resource, options.ClientId, options.CustomManagedIdentityEndpoint)
	if err != nil {
		return nil, err
	}
	return conf.TokenSource(ctx)
}

const (
	msiDefaultApiVersion = "2018-02-01"
	msiDefaultEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
)

var _ Authorizer = &ManagedIdentityAuthorizer{}

// ManagedIdentityAuthorizer is an Authorizer which supports managed service identity.
type ManagedIdentityAuthorizer struct {
	conf *managedIdentityConfig
}

// Token returns an access token acquired from the metadata endpoint.
func (a *ManagedIdentityAuthorizer) Token(ctx context.Context, _ *http.Request) (*oauth2.Token, error) {
	if a.conf == nil {
		return nil, fmt.Errorf("could not request token: conf is nil")
	}

	query := url.Values{
		"api-version": []string{a.conf.MsiApiVersion},
		"resource":    []string{a.conf.Resource},
	}

	if a.conf.ClientID != "" {
		query["client_id"] = []string{a.conf.ClientID}
	}

	url := fmt.Sprintf("%s?%s", a.conf.MsiEndpoint, query.Encode())

	body, err := retryForIMDS(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityAuthorizer: failed to request token from metadata endpoint: %v", err)
	}

	var tokenRes struct {
		AccessToken  string      `json:"access_token"`
		ClientID     string      `json:"client_id"`
		Resource     string      `json:"resource"`
		TokenType    string      `json:"token_type"`
		ExpiresIn    interface{} `json:"expires_in"`     // relative seconds from now
		ExpiresOn    interface{} `json:"expires_on"`     // timestamp
		ExtExpiresIn interface{} `json:"ext_expires_in"` // relative seconds from now
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("ManagedIdentityAuthorizer: failed to unmarshal token: %v", err)
	}

	token := &oauth2.Token{
		AccessToken: tokenRes.AccessToken,
		TokenType:   tokenRes.TokenType,
	}

	var secs time.Duration
	if exp, ok := tokenRes.ExpiresIn.(string); ok && exp != "" {
		if v, err := strconv.Atoi(exp); err == nil {
			secs = time.Duration(v)
		}
	} else if exp, ok := tokenRes.ExpiresIn.(int64); ok {
		secs = time.Duration(exp)
	} else if exp, ok := tokenRes.ExpiresIn.(float64); ok {
		secs = time.Duration(exp)
	}
	if secs > 0 {
		token.Expiry = time.Now().Add(secs * time.Second)
	}

	return token, nil
}

// AuxiliaryTokens returns additional tokens for auxiliary tenant IDs, for use in multi-tenant scenarios
func (a *ManagedIdentityAuthorizer) AuxiliaryTokens(_ context.Context, _ *http.Request) ([]*oauth2.Token, error) {
	// auxiliary tokens are not supported with MSI authentication, so just return an empty slice
	return []*oauth2.Token{}, nil
}

// managedIdentityConfig configures an ManagedIdentityAuthorizer.
type managedIdentityConfig struct {
	// ClientID is optionally used to determine which application to assume when a resource has multiple managed identities
	ClientID string

	// MsiApiVersion is the API version to use when requesting a token from the metadata service
	MsiApiVersion string

	// MsiEndpoint is the endpoint where the metadata service can be found
	MsiEndpoint string

	// Resource is the service for which to request an access token
	Resource string
}

// newManagedIdentityConfig returns a new managedIdentityConfig with a configured metadata endpoint and resource.
// clientId and objectId can be left blank when a single managed identity is available
func newManagedIdentityConfig(resource, clientId, customManagedIdentityEndpoint string) (*managedIdentityConfig, error) {
	endpoint := msiDefaultEndpoint
	if customManagedIdentityEndpoint != "" {
		endpoint = customManagedIdentityEndpoint
	}

	return &managedIdentityConfig{
		ClientID:      clientId,
		Resource:      resource,
		MsiApiVersion: msiDefaultApiVersion,
		MsiEndpoint:   endpoint,
	}, nil
}

// TokenSource provides a source for obtaining access tokens using ManagedIdentityAuthorizer.
func (c *managedIdentityConfig) TokenSource(_ context.Context) (Authorizer, error) {
	return NewCachedAuthorizer(&ManagedIdentityAuthorizer{
		conf: c,
	})
}

func azureMetadata(ctx context.Context, url string) (body []byte, statusCode int, err error) {
	ctx2, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*30))
	defer cancel()

	var req *http.Request
	req, err = http.NewRequestWithContext(ctx2, http.MethodGet, url, http.NoBody)
	if err != nil {
		return
	}
	req.Header = http.Header{
		"Metadata": []string{"true"},
	}

	client := httpClient(httpClientParams{
		instanceMetadataService: true,

		retryWaitMin:  2 * time.Second,
		retryWaitMax:  60 * time.Second,
		retryMaxCount: 5,
		timeout:       10 * time.Second,
		useProxy:      false,
	})

	var resp *http.Response
	log.Printf("[DEBUG] Performing %s Request to %q", req.Method, url)
	resp, err = client.Do(req)
	if err != nil {
		return
	}
	log.Printf("[DEBUG] Reading Body from %s %q", req.Method, url)
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if statusCode = resp.StatusCode; statusCode < 200 || statusCode > 299 {
		err = fmt.Errorf("received HTTP status %d with body: %s", resp.StatusCode, body)
		return
	}
	return
}

func retryForIMDS(ctx context.Context, url string) (body []byte, err error) {
	// see https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/how-to-use-vm-token#retry-guidance
	retries := []int{
		http.StatusRequestTimeout,      // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
	}

	// extra retry status codes specific to IMDS
	retries = append(retries,
		http.StatusNotFound,
		http.StatusGone,
		// all remaining 5xx
		http.StatusNotImplemented,
		http.StatusHTTPVersionNotSupported,
		http.StatusVariantAlsoNegotiates,
		http.StatusInsufficientStorage,
		http.StatusLoopDetected,
		http.StatusNotExtended,
		http.StatusNetworkAuthenticationRequired)

	const msiMaxAttempts = 5
	const maxDelay time.Duration = 60 * time.Second

	attempt := 0
	delay := time.Duration(0)

	for attempt < msiMaxAttempts {
		var statusCode int
		body, statusCode, err = azureMetadata(ctx, url)
		if err == nil || !hasStatusCode(statusCode, retries...) {
			return
		}

		// perform exponential backoff with a cap.
		// must increment attempt before calculating delay.
		attempt++
		// the base value of 2 is the "delta backoff" as specified in the guidance doc
		delay += (time.Duration(math.Pow(2, float64(attempt))) * time.Second)
		if delay > maxDelay {
			delay = maxDelay
		}

		select {
		case <-time.After(delay):
			// intentionally left blank
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	}

	return
}

func hasStatusCode(statusCode int, codes ...int) bool {
	for _, i := range codes {
		if i == statusCode {
			return true
		}
	}

	return false
}
