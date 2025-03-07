package main

import (
	"context"
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		serverAddr string
		localAddr  string
		subdomain  string
		secure     bool
		authToken  string
		configFile string
	)

	// Initialize viper for configuration handling
	viper.SetConfigName("burrow")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/.burrow")
	viper.AddConfigPath(".")

	rootCmd := &cobra.Command{
		Use:   "burrow",
		Short: "Burrow creates secure tunnels to your local services",
		Long:  `Burrow is an open-source alternative to ngrok that lets you expose local services behind NATs and firewalls to the internet.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Load configuration file if specified
			if configFile != "" {
				viper.SetConfigFile(configFile)
			}

			if err := viper.ReadInConfig(); err == nil {
				fmt.Println("Using config file:", viper.ConfigFileUsed())

				// Override with config file values if not explicitly set
				if cmd.Flags().Changed("server") == false && viper.IsSet("server") {
					serverAddr = viper.GetString("server")
				}
				if cmd.Flags().Changed("auth-token") == false && viper.IsSet("auth_token") {
					authToken = viper.GetString("auth_token")
				}
				if cmd.Flags().Changed("secure") == false && viper.IsSet("secure") {
					secure = viper.GetBool("secure")
				}
			}
		},
	}

	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to a Burrow server",
		Run: func(cmd *cobra.Command, args []string) {
			if serverAddr == "" {
				log.Fatal("Server address must be specified")
			}
			if localAddr == "" {
				log.Fatal("Local address must be specified")
			}

			c, err := client.New(&client.Config{
				ServerAddr: serverAddr,
				LocalAddr:  localAddr,
				Subdomain:  subdomain,
				Secure:     secure,
				AuthToken:  authToken,
			})
			if err != nil {
				log.Fatalf("Failed to create client: %v", err)
			}

			tunnelURL, err := c.Connect()
			if err != nil {
				log.Fatalf("Failed to connect: %v", err)
			}

			log.Printf("Tunnel established: %s -> %s\n", tunnelURL, localAddr)
			log.Println("Press Ctrl+C to stop")

			stop := make(chan os.Signal, 1)
			signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
			<-stop

			log.Println("Disconnecting...")
			ctx, cancel := context.WithTimeout(context.Background(), client.ShutdownTimeout)
			defer cancel()

			if err := c.Disconnect(ctx); err != nil {
				log.Fatalf("Failed to disconnect: %v", err)
			}

			log.Println("Disconnected")
		},
	}

	// Add global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Config file (default is $HOME/.burrow/burrow.yaml)")

	// Add flags to connect command
	connectCmd.Flags().StringVarP(&serverAddr, "server", "s", "", "Burrow server address (required)")
	connectCmd.Flags().StringVarP(&localAddr, "local", "l", "localhost:8080", "Local service address")
	connectCmd.Flags().StringVarP(&subdomain, "subdomain", "n", "", "Custom subdomain (optional)")
	connectCmd.Flags().BoolVarP(&secure, "secure", "", false, "Use secure WebSocket connection (wss://)")
	connectCmd.Flags().StringVarP(&authToken, "auth-token", "t", "", "Authentication token (if required by server)")

	// Add version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Burrow version 0.1.0")
		},
	}

	// Add commands to root
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(versionCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
