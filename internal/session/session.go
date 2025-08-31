package session

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PrebenVerEecke/omnidocsscanner/internal/client"
)

// Session holds authentication state
type Session struct {
	Client     *client.Client
	BaseURL    string
	Cookies    *cookiejar.Jar
	JWTToken   string
	JWTExpiry  time.Time
	CSRFToken  string
	Username   string
	Password   string
}

// New creates a new session with the given client and base URL
func New(c *client.Client, baseURL string) (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	c.Client.Jar = jar

	return &Session{
		Client:  c,
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Cookies: jar,
	}, nil
}

// SetCredentials sets the username and password for the session
func (s *Session) SetCredentials(username, password string) {
	s.Username = username
	s.Password = password
}

// SetJWT sets the JWT token and expiry
func (s *Session) SetJWT(token string, expiry time.Time) {
	s.JWTToken = token
	s.JWTExpiry = expiry
}

// IsJWTExpired checks if the JWT token is expired
func (s *Session) IsJWTExpired() bool {
	return s.JWTToken != "" && time.Now().After(s.JWTExpiry)
}

// GetAuthHeader returns the appropriate authorization header
func (s *Session) GetAuthHeader() string {
	if s.JWTToken != "" && !s.IsJWTExpired() {
		return "Bearer " + s.JWTToken
	}
	return ""
}

// AddAuthHeader adds authentication header to the request
func (s *Session) AddAuthHeader(req *http.Request) {
	if authHeader := s.GetAuthHeader(); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
}

// AddCSRFToken adds CSRF token to the request if available
func (s *Session) AddCSRFToken(req *http.Request) {
	if s.CSRFToken != "" {
		// Common CSRF header names
		csrfHeaders := []string{
			"X-CSRF-Token",
			"X-XSRF-TOKEN",
			"CSRF-Token",
			"_csrf",
		}
		for _, header := range csrfHeaders {
			req.Header.Set(header, s.CSRFToken)
		}
	}
}

// DiscoverCSRFToken attempts to discover CSRF token from a response
func (s *Session) DiscoverCSRFToken(resp *http.Response) {
	// Check response headers for CSRF token
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		s.CSRFToken = token
		return
	}

	// TODO: Parse HTML body for hidden CSRF input fields
	// This would require reading the response body and parsing with goquery
}

// GetCookies returns all cookies for the base URL
func (s *Session) GetCookies() []*http.Cookie {
	parsedURL, _ := url.Parse(s.BaseURL)
	return s.Cookies.Cookies(parsedURL)
}

// Clear clears all session data
func (s *Session) Clear() {
	s.JWTToken = ""
	s.JWTExpiry = time.Time{}
	s.CSRFToken = ""
	s.Username = ""
	s.Password = ""

	// Clear cookies
	if s.Cookies != nil {
		parsedURL, _ := url.Parse(s.BaseURL)
		s.Cookies.SetCookies(parsedURL, nil)
	}
}
