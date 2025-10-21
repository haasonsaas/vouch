package posture

import (
	"context"
	"fmt"
	"os"
	"time"
)

type Report struct {
	NodeID         string    `json:"node_id"`
	Hostname       string    `json:"hostname"`
	OSRelease      string    `json:"os_release"`
	Kernel         string    `json:"kernel"`
	LastUpdateTime int64     `json:"last_update_time"`
	DiskEncrypted  bool      `json:"disk_encrypted"`
	Services       []string  `json:"services"`
	Timestamp      time.Time `json:"timestamp"`
}

func Collect() (*Report, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("determine hostname: %w", err)
	}

	// New CollectorV2 handles posture gathering with richer detail
	collector := NewCollectorV2(10 * time.Second)
	reportV2 := collector.Collect(context.Background())

	// Map back to legacy Report until callers migrate
	return &Report{
		NodeID:         reportV2.NodeID,
		Hostname:       hostname,
		OSRelease:      reportV2.OSName,
		Kernel:         reportV2.Kernel,
		LastUpdateTime: reportV2.CollectedAt.Unix(),
		DiskEncrypted:  reportV2.RootVolumeEncrypted,
		Services:       reportV2.CriticalServices,
		Timestamp:      reportV2.CollectedAt,
	}, nil
}
