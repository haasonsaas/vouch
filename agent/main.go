package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/haasonsaas/vouch/pkg/posture"
)

var (
	serverURL = flag.String("server", "http://localhost:8080", "Vouch server URL")
	interval  = flag.Duration("interval", 5*time.Minute, "Report interval")
	Version   = "dev"
)

func main() {
	flag.Parse()
	
	log.Printf("Vouch Agent %s starting...", Version)
	log.Printf("Server: %s", *serverURL)
	log.Printf("Report interval: %s", *interval)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Report immediately on startup
	reportPosture()

	// Then report on interval
	for range ticker.C {
		reportPosture()
	}
}

func reportPosture() {
	report, err := posture.Collect()
	if err != nil {
		log.Printf("Error collecting posture: %v", err)
		return
	}

	data, err := json.Marshal(report)
	if err != nil {
		log.Printf("Error marshaling report: %v", err)
		return
	}

	resp, err := http.Post(
		*serverURL+"/v1/report",
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		log.Printf("Error sending report: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Server returned status %d", resp.StatusCode)
		return
	}

	log.Printf("✅ Reported posture for %s", report.Hostname)
}
