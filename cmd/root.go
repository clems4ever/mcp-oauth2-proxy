package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/oidc"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/server"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "mcp-oauth2-proxy",
	Short: "OAuth2 authorization server (client credentials grant)",
	Long:  `mcp-oauth2-proxy is an OAuth2 authorization server implementing the client credentials grant for multiple configured applications.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		var st *store.Store
		if cfg.Storage.Path != "" {
			st, err = store.Open(cfg.Storage.Path)
			if err != nil {
				return fmt.Errorf("opening storage: %w", err)
			}
			defer func() { _ = st.Close() }()
			log.Printf("persisting refresh tokens to %s", cfg.Storage.Path)
		} else {
			st = store.New()
		}

		var oidcClient *oidc.Client
		if cfg.OIDCEnabled() {
			oidcClient, err = oidc.New(context.Background(), cfg.OIDC)
			if err != nil {
				return fmt.Errorf("initializing OIDC provider: %w", err)
			}
			log.Printf("OIDC login enabled for issuer %s", cfg.OIDC.Issuer)
		}

		srv := server.New(cfg, st, oidcClient)
		log.Printf("starting OAuth2 server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	},
}

// Execute runs the root command, printing any error to stderr and exiting
// non-zero on failure.
//
// @testcase TestConfigFlagRegistered verifies the root command is wired with its flags.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// init registers the --config persistent flag with its default path.
//
// @testcase TestConfigFlagRegistered verifies the --config flag is registered with a default.
func init() {
	defaultCfg := filepath.Join(os.Getenv("HOME"), ".mcp-oauth2.yaml")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", defaultCfg, "path to the config file")
}
