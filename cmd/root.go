package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aws-vpn-saml",
	Short: "A helper for AWS VPN authentication",
	Long:  `A helper application to handle the SAML authentication flow for AWS Client VPN.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
