package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

type StatusLevel string

const (
	Healthy  StatusLevel = "healthy"
	Warning  StatusLevel = "warning"
	Critical StatusLevel = "critical"
	Unknown  StatusLevel = "unknown"
)

type CheckResult struct {
	Name    string      `json:"name"`
	Status  StatusLevel `json:"status"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

type HealthReport struct {
	Hostname      string        `json:"hostname"`
	OverallStatus StatusLevel   `json:"overall_status"`
	UptimeSeconds uint64        `json:"uptime_seconds"`
	Checks        []CheckResult `json:"checks"`
}

var (
	state     HealthReport
	stateLock sync.RWMutex
)

func worst(a, b StatusLevel) StatusLevel {
	if a == Critical || b == Critical {
		return Critical
	}
	if a == Warning || b == Warning {
		return Warning
	}
	if a == Healthy && b == Healthy {
		return Healthy
	}
	return Unknown
}

func main() {
	// initial collection
	refreshChecks()

	// periodic refresh
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshChecks()
		}
	}()

	// HTTP server
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		stateLock.RLock()
		defer stateLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})

	addr := ":8080"
	fmt.Println("NMS Agent running at http://" + getLocalIP() + addr + "/metrics")
	http.ListenAndServe(addr, nil)
}

func refreshChecks() {
	var checks []CheckResult

	hostname, _ := os.Hostname()
	uptime, _ := host.Uptime()

	checks = append(checks, checkCPU())
	checks = append(checks, checkMemory())
	checks = append(checks, checkDisks())
	checks = append(checks, checkNetwork())
	checks = append(checks, checkSmart())
	checks = append(checks, checkMdRaid())
	checks = append(checks, checkIPMI())

	overall := Healthy
	for _, c := range checks {
		overall = worst(overall, c.Status)
	}

	report := HealthReport{
		Hostname:      hostname,
		OverallStatus: overall,
		UptimeSeconds: uptime,
		Checks:        checks,
	}

	stateLock.Lock()
	state = report
	stateLock.Unlock()
}

// --- Checks ---

func checkCPU() CheckResult {
	usage, _ := cpu.Percent(time.Second, false)
	if len(usage) == 0 {
		return CheckResult{"cpu", Unknown, "cpu usage unavailable", nil}
	}
	val := usage[0]
	if val > 90 {
		return CheckResult{"cpu", Critical, fmt.Sprintf("high cpu usage: %.1f%%", val), nil}
	} else if val > 70 {
		return CheckResult{"cpu", Warning, fmt.Sprintf("elevated cpu usage: %.1f%%", val), nil}
	}
	return CheckResult{"cpu", Healthy, fmt.Sprintf("cpu ok: %.1f%%", val), nil}
}

func checkMemory() CheckResult {
	vm, _ := mem.VirtualMemory()
	percent := vm.UsedPercent
	if percent > 90 {
		return CheckResult{"memory", Critical, fmt.Sprintf("memory high: %.1f%%", percent), nil}
	} else if percent > 75 {
		return CheckResult{"memory", Warning, fmt.Sprintf("memory elevated: %.1f%%", percent), nil}
	}
	return CheckResult{"memory", Healthy, fmt.Sprintf("memory ok: %.1f%%", percent), nil}
}

func checkDisks() CheckResult {
	parts, _ := disk.Partitions(false)
	var used, total uint64
	for _, p := range parts {
		du, err := disk.Usage(p.Mountpoint)
		if err == nil {
			used += du.Used
			total += du.Total
		}
	}
	if total == 0 {
		return CheckResult{"disk_usage", Unknown, "no disks found", nil}
	}
	percent := float64(used) / float64(total) * 100
	if percent > 90 {
		return CheckResult{"disk_usage", Critical, fmt.Sprintf("disk usage %.1f%%", percent), nil}
	} else if percent > 80 {
		return CheckResult{"disk_usage", Warning, fmt.Sprintf("disk usage %.1f%%", percent), nil}
	}
	return CheckResult{"disk_usage", Healthy, fmt.Sprintf("disk usage %.1f%%", percent), nil}
}

func checkNetwork() CheckResult {
    ifaces, _ := gnet.Interfaces()
    problems := []string{}

    for _, iface := range ifaces {
        if iface.Name == "lo" {
            continue
        }

        up := false
        for _, f := range iface.Flags {
            if strings.ToLower(f) == "up" {
                up = true
                break
            }
        }

        if !up {
            problems = append(problems, fmt.Sprintf("%s is down", iface.Name))
        }
    }

    if len(problems) == 0 {
        return CheckResult{"network", Healthy, "all interfaces OK", nil}
    }
    return CheckResult{"network", Warning, "issues: " + strings.Join(problems, "; "), nil}
}


func checkSmart() CheckResult {
	if _, err := exec.LookPath("smartctl"); err != nil {
		return CheckResult{"smartctl", Unknown, "smartctl not installed", nil}
	}
	out, err := exec.Command("smartctl", "--scan").Output()
	if err != nil {
		return CheckResult{"smartctl", Unknown, "failed smartctl --scan", nil}
	}
	lines := strings.Split(string(out), "\n")
	var criticals, warnings []string
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		dev := strings.Fields(l)[0]
		cmd := exec.Command("smartctl", "-H", dev)
		o, _ := cmd.Output()
		s := string(o)
		if strings.Contains(s, "PASSED") {
			continue
		} else if strings.Contains(s, "FAILED") {
			criticals = append(criticals, dev+" FAILED")
		} else {
			warnings = append(warnings, dev+" unknown state")
		}
	}
	if len(criticals) > 0 {
		return CheckResult{"smart", Critical, "SMART critical: " + strings.Join(criticals, "; "), nil}
	}
	if len(warnings) > 0 {
		return CheckResult{"smart", Warning, "SMART warnings: " + strings.Join(warnings, "; "), nil}
	}
	return CheckResult{"smart", Healthy, "all disks SMART OK", nil}
}

func checkMdRaid() CheckResult {
	data, err := ioutil.ReadFile("/proc/mdstat")
	if err != nil || len(data) == 0 {
		return CheckResult{"md_raid", Unknown, "mdstat not available", nil}
	}
	s := string(data)
	if strings.Contains(s, "degraded") || strings.Contains(s, "inactive") {
		return CheckResult{"md_raid", Critical, "md RAID degraded/inactive", nil}
	}
	return CheckResult{"md_raid", Healthy, "software RAID OK", nil}
}

func checkIPMI() CheckResult {
	if _, err := exec.LookPath("ipmitool"); err != nil {
		return CheckResult{"ipmi", Unknown, "ipmitool not installed", nil}
	}
	out, err := exec.Command("ipmitool", "sensor").Output()
	if err != nil {
		return CheckResult{"ipmi", Unknown, "failed ipmitool", nil}
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "critical") || strings.Contains(s, "fail") {
		return CheckResult{"ipmi", Critical, "IPMI sensor reports critical", nil}
	}
	if strings.Contains(s, "na") || strings.Contains(s, "ns") {
		return CheckResult{"ipmi", Warning, "IPMI sensor contains NA/NS", nil}
	}
	return CheckResult{"ipmi", Healthy, "IPMI sensors OK", nil}
}

// Utility: get IP for logging
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}
