package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds HTTP server and token settings.
type ServerConfig struct {
	Port        int    `yaml:"port"`
	Issuer      string `yaml:"issuer"`
	JWTSecret   string `yaml:"jwt_secret"`
	TokenTTL    int    `yaml:"token_ttl"`     // access token lifetime, seconds
	AuthCodeTTL int    `yaml:"auth_code_ttl"` // authorization code lifetime, seconds
	UpstreamURL string `yaml:"upstream_url"`  // MCP HTTP server to proxy unhandled requests to
}

// User is a human user that can authenticate at the authorization endpoint.
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Application is the single OAuth2 client used for the client_credentials grant
// and the authorization code flow.
type Application struct {
	ClientID      string   `yaml:"client_id"`
	ClientSecret  string   `yaml:"client_secret"`
	AllowedScopes []string `yaml:"allowed_scopes"`
	RedirectURIs  []string `yaml:"redirect_uris"`
}

// OIDCConfig configures an upstream OpenID Connect provider (e.g. Google) used
// as an alternative browser login alongside the local password form.
type OIDCConfig struct {
	Issuer        string   `yaml:"issuer"`        // e.g. https://accounts.google.com
	ClientID      string   `yaml:"client_id"`     // OAuth client ID registered with the provider
	ClientSecret  string   `yaml:"client_secret"` // OAuth client secret
	RedirectURL   string   `yaml:"redirect_url"`  // this proxy's callback; defaults to <issuer base URL>/oauth2/oidc/callback
	Scopes        []string `yaml:"scopes"`        // requested scopes; defaults to [openid, email, profile]
	AllowedEmails []string `yaml:"allowed_emails"`// only these verified emails may authenticate
}

// Config is the root configuration.
type Config struct {
	Server      ServerConfig `yaml:"server"`
	Users       []User       `yaml:"users"`
	Application  Application  `yaml:"application"`
	OIDC        *OIDCConfig  `yaml:"oidc"`
}

// OIDCEnabled reports whether an OIDC provider is configured.
//
// @return bool True when an oidc block is present in the configuration.
//
// @testcase TestLoad_OIDCDefaults verifies OIDCEnabled is true when an oidc block is loaded.
func (c *Config) OIDCEnabled() bool {
	return c.OIDC != nil
}

// Load reads and parses the YAML config file at the given path.
//
// @arg path Filesystem path to the YAML configuration file.
// @return *Config The parsed configuration with defaults applied.
// @error Returns an error if the file cannot be read, parsed, or fails validation.
//
// @testcase TestLoad_AppliesDefaults verifies defaults are filled in for unset fields.
// @testcase TestLoad_KeepsExplicitValues verifies explicit values are preserved.
// @testcase TestLoad_MissingFile verifies a missing file is an error.
// @testcase TestLoad_InvalidYAML verifies invalid YAML is an error.
// @testcase TestLoad_OIDCMissingRequiredFields verifies an incomplete oidc block is rejected.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.TokenTTL == 0 {
		cfg.Server.TokenTTL = 3600
	}
	if cfg.Server.AuthCodeTTL == 0 {
		cfg.Server.AuthCodeTTL = 300
	}
	if cfg.Server.Issuer == "" {
		cfg.Server.Issuer = fmt.Sprintf("http://localhost:%d", cfg.Server.Port)
	}

	if cfg.OIDC != nil {
		if err := cfg.OIDC.validate(cfg.Server.Issuer); err != nil {
			return nil, fmt.Errorf("invalid oidc config: %w", err)
		}
	}

	return &cfg, nil
}

// validate checks required OIDC fields and fills in defaults. issuerBaseURL is
// the proxy's public base URL, used to derive the callback when redirect_url is
// not set explicitly.
//
// @arg issuerBaseURL The proxy's public base URL used to derive the default redirect_url.
// @error Returns an error if a required OIDC field (issuer, client_id, client_secret, allowed_emails) is missing.
//
// @testcase TestLoad_OIDCDefaults verifies defaults for scopes and redirect_url are applied.
// @testcase TestLoad_OIDCMissingRequiredFields verifies missing required fields are rejected.
func (o *OIDCConfig) validate(issuerBaseURL string) error {
	if o.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if o.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if len(o.AllowedEmails) == 0 {
		return fmt.Errorf("allowed_emails must list at least one address")
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "email", "profile"}
	}
	if o.RedirectURL == "" {
		o.RedirectURL = strings.TrimRight(issuerBaseURL, "/") + "/oauth2/oidc/callback"
	}
	return nil
}

// FindUser returns the user with the given username, or nil.
//
// @arg username The username to look up.
// @return *User The matching user, or nil if none matches.
//
// @testcase TestFindUser verifies a known user is found and an unknown one returns nil.
func (c *Config) FindUser(username string) *User {
	for i := range c.Users {
		if c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}
