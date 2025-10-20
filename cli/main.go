package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	Version   = "dev"
)

type Device struct {
	Hostname   string    `json:"hostname"`
	NodeID     string    `json:"node_id"`
	Compliant  bool      `json:"compliant"`
	LastSeen   time.Time `json:"last_seen"`
	Violations string    `json:"violations"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "vouch",
		Short: "Vouch - Device attestation for Tailscale",
		Long:  "Manage device compliance and security posture for your Tailscale network",
	}

	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", "http://localhost:8080", "Vouch server URL")

	rootCmd.AddCommand(
		statusCmd(),
		devicesCmd(),
		deviceCmd(),
		versionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show overall compliance status",
		RunE: func(cmd *cobra.Command, args []string) error {
			devices, err := fetchDevices()
			if err != nil {
				return err
			}

			compliant := 0
			for _, d := range devices {
				if d.Compliant {
					compliant++
				}
			}

			fmt.Printf("Vouch Status\n")
			fmt.Printf("============\n\n")
			fmt.Printf("Total Devices:     %d\n", len(devices))
			fmt.Printf("Compliant:         %d ✅\n", compliant)
			fmt.Printf("Non-compliant:     %d ❌\n", len(devices)-compliant)
			fmt.Printf("Compliance Rate:   %.1f%%\n", float64(compliant)/float64(len(devices))*100)

			return nil
		},
	}
}

func devicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "devices",
		Aliases: []string{"ls", "list"},
		Short:   "List all devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			devices, err := fetchDevices()
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "HOSTNAME\tSTATUS\tLAST SEEN\tVIOLATIONS")
			fmt.Fprintln(w, "--------\t------\t---------\t----------")

			for _, d := range devices {
				status := "✅"
				if !d.Compliant {
					status = "❌"
				}
				lastSeen := time.Since(d.LastSeen).Round(time.Second)
				fmt.Fprintf(w, "%s\t%s\t%s ago\t%s\n", d.Hostname, status, lastSeen, d.Violations)
			}

			w.Flush()
			return nil
		},
	}
}

func deviceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "device [hostname]",
		Short: "Show details for a specific device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			device, err := fetchDevice(hostname)
			if err != nil {
				return err
			}

			fmt.Printf("Device: %s\n", device.Hostname)
			fmt.Printf("========================================\n\n")
			fmt.Printf("Node ID:      %s\n", device.NodeID)
			fmt.Printf("Compliant:    %v\n", device.Compliant)
			fmt.Printf("Last Seen:    %s (%s ago)\n", device.LastSeen.Format(time.RFC3339), time.Since(device.LastSeen).Round(time.Second))
			fmt.Printf("Violations:   %s\n", device.Violations)

			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vouch version %s\n", Version)
		},
	}
}

func fetchDevices() ([]Device, error) {
	resp, err := http.Get(serverURL + "/v1/devices")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var devices []Device
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, err
	}

	return devices, nil
}

func fetchDevice(hostname string) (*Device, error) {
	resp, err := http.Get(serverURL + "/v1/devices/" + hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device not found")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var device Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, err
	}

	return &device, nil
}
