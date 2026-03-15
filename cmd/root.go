package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/clems4ever/mcp-oauth2-go/config"
	"github.com/clems4ever/mcp-oauth2-go/internal/server"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "mcp-oauth2-go",
	Short: "OAuth2 authorization server (client credentials grant)",
	Long:  `mcp-oauth2-go is an OAuth2 authorization server implementing the client credentials grant for multiple configured applications.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		srv := server.New(cfg)
		log.Printf("starting OAuth2 server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	defaultCfg := filepath.Join(os.Getenv("HOME"), ".mcp-oauth2.yaml")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", defaultCfg, "path to the config file")
}
