package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PrebenVerEecke/omnidocsscanner/internal/session"
)

// Authenticator interface for different authentication methods
type Authenticator interface {
	Login(ctx context.Context, sess *session.Session, baseURL, user, pass string) (*session.Session, error)
	Name() string
}

// LoginResponse represents a JSON login response
type LoginResponse struct {
	Token     string `json:"token"`
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn int    `json:"expires_in"`
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Error     string `json:"error"`
}

// FormSessionAuth implements form-based authentication
type FormSessionAuth struct {
	LoginPaths []string
}

// NewFormSessionAuth creates a new form session authenticator
func NewFormSessionAuth() *FormSessionAuth {
	return &FormSessionAuth{
		LoginPaths: []string{
			"/login",
			"/auth/login",
			"/api/auth/login",
			"/authenticate",
			"/signin",
		},
	}
}

// Name returns the authenticator name
func (f *FormSessionAuth) Name() string {
	return "form-session"
}

// Login attempts to authenticate using form-based login
func (f *FormSessionAuth) Login(ctx context.Context, sess *session.Session, baseURL, user, pass string) (*session.Session, error) {
	for _, loginPath := range f.LoginPaths {
		if err := f.tryLoginPath(ctx, sess, baseURL, loginPath, user, pass); err == nil {
			return sess, nil
		}
	}
	return nil, fmt.Errorf("all login paths failed")
}

func (f *FormSessionAuth) tryLoginPath(ctx context.Context, sess *session.Session, baseURL, loginPath, user, pass string) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + loginPath

	// First, try to get the login page to discover any CSRF tokens or form fields
	getReq, err := http.NewRequestWithContext(ctx, "GET", loginURL, nil)
	if err != nil {
		return err
	}

	resp, err := sess.Client.Do(getReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Discover CSRF token from the response
	sess.DiscoverCSRFToken(resp)

	// Prepare login data
	data := url.Values{}
	data.Set("username", user)
	data.Set("password", pass)
	data.Set("submit", "Login")

	// Add CSRF token if discovered
	if sess.CSRFToken != "" {
		data.Set("csrf_token", sess.CSRFToken)
		// Try common CSRF field names
		data.Set("_csrf", sess.CSRFToken)
		data.Set("authenticity_token", sess.CSRFToken)
	}

	// Create POST request
	postReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sess.AddCSRFToken(postReq)

	// Perform login
	resp, err = sess.Client.Do(postReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if login was successful (status 200 or redirect to dashboard/home)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		sess.SetCredentials(user, pass)
		return nil
	}

	return fmt.Errorf("login failed with status %d", resp.StatusCode)
}

// JWTAuth implements JWT-based authentication
type JWTAuth struct {
	LoginPaths []string
}

// NewJWTAuth creates a new JWT authenticator
func NewJWTAuth() *JWTAuth {
	return &JWTAuth{
		LoginPaths: []string{
			"/api/auth/login",
			"/api/login",
			"/auth/login",
			"/api/v1/auth/login",
			"/oauth/token",
		},
	}
}

// Name returns the authenticator name
func (j *JWTAuth) Name() string {
	return "jwt"
}

// Login attempts to authenticate using JWT
func (j *JWTAuth) Login(ctx context.Context, sess *session.Session, baseURL, user, pass string) (*session.Session, error) {
	for _, loginPath := range j.LoginPaths {
		if err := j.tryJWTLogin(ctx, sess, baseURL, loginPath, user, pass); err == nil {
			return sess, nil
		}
	}
	return nil, fmt.Errorf("all JWT login paths failed")
}

func (j *JWTAuth) tryJWTLogin(ctx context.Context, sess *session.Session, baseURL, loginPath, user, pass string) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + loginPath

	// Prepare login payload
	loginData := map[string]string{
		"username": user,
		"password": pass,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return err
	}

	// Create POST request
	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	// Perform login
	resp, err := sess.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse response
	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return err
	}

	// Check for success
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && (loginResp.Token != "" || loginResp.AccessToken != "") {
		token := loginResp.Token
		if token == "" {
			token = loginResp.AccessToken
		}

		// Set JWT token (we'll parse expiry later if available)
		sess.SetJWT(token, time.Now().Add(time.Hour)) // Default 1 hour expiry
		sess.SetCredentials(user, pass)
		return nil
	}

	return fmt.Errorf("JWT login failed with status %d: %s", resp.StatusCode, loginResp.Error)
}
