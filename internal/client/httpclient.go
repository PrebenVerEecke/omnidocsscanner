package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"
)

const (
	UserAgent = "newgenone-pentest/0.1.0"
)

// Config holds HTTP client configuration
type Config struct {
	Timeout     time.Duration
	RateLimit   float64
	Proxy       string
	InsecureTLS bool
}

// Client wraps http.Client with additional features
type Client struct {
	*http.Client
	limiter *rate.Limiter
}

// New creates a new HTTP client with the specified configuration
func New(cfg Config) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
		},
	}

	// Configure proxy if provided
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Create rate limiter
	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}

	// Create HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	client := &Client{
		Client:  httpClient,
		limiter: limiter,
	}

	// Wrap transport with rate limiting and user agent
	client.Client.Transport = &rateLimitedTransport{
		roundTripper: transport,
		limiter:      limiter,
		userAgent:    UserAgent,
	}

	return client, nil
}

// Do performs an HTTP request with rate limiting
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(req.Context()); err != nil {
			return nil, fmt.Errorf("rate limit error: %w", err)
		}
	}
	return c.Client.Do(req)
}

// rateLimitedTransport wraps http.RoundTripper with rate limiting and user agent
type rateLimitedTransport struct {
	roundTripper http.RoundTripper
	limiter      *rate.Limiter
	userAgent    string
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply rate limiting
	if t.limiter != nil {
		if err := t.limiter.Wait(req.Context()); err != nil {
			return nil, fmt.Errorf("rate limit error: %w", err)
		}
	}

	// Set user agent if not already set
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.userAgent)
	}

	// Perform the request
	return t.roundTripper.RoundTrip(req)
}

// WaitForRateLimit blocks until the rate limiter allows the request
func (c *Client) WaitForRateLimit(ctx context.Context) error {
	if c.limiter != nil {
		return c.limiter.Wait(ctx)
	}
	return nil
}

// GetRateLimiter returns the current rate limiter
func (c *Client) GetRateLimiter() *rate.Limiter {
	return c.limiter
}

// SetRateLimit updates the rate limit
func (c *Client) SetRateLimit(rps float64) {
	if rps > 0 {
		c.limiter = rate.NewLimiter(rate.Limit(rps), 1)
		if rt, ok := c.Client.Transport.(*rateLimitedTransport); ok {
			rt.limiter = c.limiter
		}
	} else {
		c.limiter = nil
		if rt, ok := c.Client.Transport.(*rateLimitedTransport); ok {
			rt.limiter = nil
		}
	}
}
