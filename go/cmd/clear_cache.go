package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var clearCacheCmd = &cobra.Command{
	Use:   "clear-cache",
	Short: "Clear cached SAML session",
	Long:  `This command removes the cached SAML session, forcing a new login on next connection.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clearSecureSession(); err != nil {
			fmt.Printf("Error clearing cache: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("Session cache cleared successfully")
	},
}

func clearSecureSession() error {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache")
	}
	
	cacheFile := filepath.Join(cacheDir, "aws-vpn", "session.json")
	
	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear session cache: %w", err)
	}
	
	return nil
}

func init() {
	rootCmd.AddCommand(clearCacheCmd)
}
