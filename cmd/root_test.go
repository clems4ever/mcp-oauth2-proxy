package cmd

import "testing"

// TestConfigFlagRegistered verifies the --config persistent flag is registered with a default path.
//
// @arg t The testing context provided by the Go test runner.
func TestConfigFlagRegistered(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("config")
	if f == nil {
		t.Fatal("expected --config flag to be registered")
	}
	if f.DefValue == "" {
		t.Error("expected a non-empty default config path")
	}
}
