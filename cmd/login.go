package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

const (
	awsVpnUrl = "https://self-service.clientvpn.amazonaws.com/api/auth/saml/initiate?connection_id="
)

var ovpnConfigPath string
var serverShutdown = make(chan bool)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Perform interactive browser-based login",
	Long:  `This command starts the SAML authentication flow, opening a browser window for you to log in with your identity provider.`,
	Run: func(cmd *cobra.Command, args []string) {
		connectionID, err := getConnectionID(ovpnConfigPath)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}

		fmt.Println("Starting local server on http://localhost:8080")
		http.HandleFunc("/", handleSamlResponse)

		server := &http.Server{Addr: ":8080"}

		go func() {
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				fmt.Printf("Failed to start server: %s\n", err)
			}
		}()

		fullUrl := awsVpnUrl + connectionID
		fmt.Printf("Opening browser to: %s\n", fullUrl)
		openBrowser(fullUrl)

		<-serverShutdown
		fmt.Println("Shutting down server...")
		server.Shutdown(nil)
	},
}

func getConnectionID(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open ovpn config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`cvpn-endpoint-([a-f0-9]+)\.prod\.clientvpn`)
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if len(matches) > 1 {
			return matches[1], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading ovpn config file: %w", err)
	}

	return "", fmt.Errorf("could not find connection ID in ovpn config file")
}

func handleSamlResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	samlResponse, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		http.Error(w, "Failed to decode SAML response", http.StatusBadRequest)
		return
	}

	connectionID, err := getConnectionID(ovpnConfigPath)
	if err != nil {
		http.Error(w, "Failed to get connection ID", http.StatusInternalServerError)
		return
	}

	if err := saveSecureSession(string(samlResponse), connectionID, 8); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	fmt.Println("Received and cached SAML response.")
	fmt.Fprintf(w, "Authentication successful! You can close this window.")
	serverShutdown <- true
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		fmt.Printf("Failed to open browser: %s\n", err)
	}
}

func saveSecureSession(samlAssertion, connectionID string, ttlHours int) error {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache")
	}
	
	awsVpnCache := filepath.Join(cacheDir, "aws-vpn")
	if err := os.MkdirAll(awsVpnCache, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	cacheFile := filepath.Join(awsVpnCache, "session.json")
	
	session := map[string]interface{}{
		"saml_assertion": samlAssertion,
		"connection_id":  connectionID,
		"expires_at":     time.Now().Add(time.Duration(ttlHours) * time.Hour).Unix(),
		"created_at":     time.Now().Unix(),
	}
	
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	
	if err := os.WriteFile(cacheFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write session cache: %w", err)
	}
	
	return nil
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&ovpnConfigPath, "config", "c", "", "Path to the .ovpn configuration file (required)")
	loginCmd.MarkFlagRequired("config")
}
