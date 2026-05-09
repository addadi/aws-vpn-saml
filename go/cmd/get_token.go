package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

const (
	getTokenAwsVpnUrl = "https://self-service.clientvpn.amazonaws.com/api/auth/saml/app"
)

var getTokenOvpnConfigPath string

var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Get a short-lived OpenVPN token",
	Long:  `This command retrieves a short-lived OpenVPN session token from AWS using the cached SAML assertion.`,
	Run: func(cmd *cobra.Command, args []string) {
		connectionID, err := getConnectionID(getTokenOvpnConfigPath)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}

		samlAssertion, err := loadSecureSession(connectionID)
		if err != nil {
			fmt.Printf("Error loading cached session: %s\n", err)
			fmt.Println("Please run 'login' command first")
			os.Exit(1)
		}

		reqBody, err := json.Marshal(map[string]string{
			"connection_id":  connectionID,
			"saml_response": samlAssertion,
		})
		if err != nil {
			fmt.Printf("Error marshalling JSON: %s\n", err)
			os.Exit(1)
		}

		resp, err := http.Post(getTokenAwsVpnUrl, "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			fmt.Printf("Error making request to AWS: %s\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response body: %s\n", err)
			os.Exit(1)
		}

		fmt.Println(string(respBody))
	},
}

func loadSecureSession(connectionID string) (string, error) {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache")
	}
	
	cacheFile := filepath.Join(cacheDir, "aws-vpn", "session.json")
	
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no cached session found")
		}
		return "", fmt.Errorf("failed to read session cache: %w", err)
	}
	
	var session map[string]interface{}
	if err := json.Unmarshal(data, &session); err != nil {
		return "", fmt.Errorf("failed to unmarshal session: %w", err)
	}
	
	// Validate expiration
	if expiresAt, ok := session["expires_at"].(float64); ok {
		if time.Now().Unix() > int64(expiresAt) {
			return "", fmt.Errorf("cached session expired")
		}
	}
	
	// Validate connection ID
	if cachedID, ok := session["connection_id"].(string); ok {
		if cachedID != connectionID {
			return "", fmt.Errorf("cached session for different connection")
		}
	}
	
	samlAssertion, ok := session["saml_assertion"].(string)
	if !ok {
		return "", fmt.Errorf("invalid session format")
	}
	
	return samlAssertion, nil
}

func init() {
	rootCmd.AddCommand(getTokenCmd)
	getTokenCmd.Flags().StringVarP(&getTokenOvpnConfigPath, "config", "c", "", "Path to the .ovpn configuration file (required)")
	getTokenCmd.MarkFlagRequired("config")
}
