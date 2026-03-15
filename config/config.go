package config

import (
	"fmt"
	"os"

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

// Config is the root configuration.
type Config struct {
	Server      ServerConfig `yaml:"server"`
	Users       []User       `yaml:"users"`
	Application Application  `yaml:"application"`
}

// Load reads and parses the YAML config file at the given path.
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

	return &cfg, nil
}

// FindUser returns the user with the given username, or nil.
func (c *Config) FindUser(username string) *User {
	for i := range c.Users {
		if c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}
