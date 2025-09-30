package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
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
	OS            string        `json:"os"`
	Platform      string        `json:"platform"`
	PlatformVer   string        `json:"platform_version"`
	Kernel        string        `json:"kernel"`
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
	refreshChecks()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshChecks()
		}
	}()

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
	info, _ := host.Info()

	checks = append(checks, checkCPU())
	checks = append(checks, checkMemory())
	checks = append(checks, checkDisks())
	checks = append(checks, checkNetwork())
	checks = append(checks, checkSmart())
	checks = append(checks, checkMdRaid())
	checks = append(checks, checkIPMI())
	checks = append(checks, checkLoad())
	checks = append(checks, checkProcesses())

	overall := Healthy
	for _, c := range checks {
		overall = worst(overall, c.Status)
	}

	report := HealthReport{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Platform:      info.Platform,
		PlatformVer:   info.PlatformVersion,
		Kernel:        info.KernelVersion,
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
    if runtime.GOOS == "windows" {
        out, err := exec.Command("wmic", "diskdrive", "get", "status,model").Output()
        if err != nil {
            return CheckResult{"smartctl", Unknown, "failed to query SMART status using WMIC", nil}
        }

        output := string(out)
        if strings.Contains(output, "OK") {
            return CheckResult{"smart", Healthy, "SMART status OK", nil}
        }
        return CheckResult{"smart", Critical, "SMART status indicates an issue", nil}
    }

    // Linux-specific smartctl check (already implemented)
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
    if runtime.GOOS == "windows" {
        out, err := exec.Command("wmic", "logicaldisk", "get", "status,deviceid").Output()
        if err != nil {
            return CheckResult{"md_raid", Unknown, "failed to query RAID status using WMIC", nil}
        }

        output := string(out)
        if strings.Contains(output, "OK") {
            return CheckResult{"md_raid", Healthy, "RAID status OK", nil}
        }
        return CheckResult{"md_raid", Critical, "RAID status indicates an issue", nil}
    }

    // Linux-specific mdstat check (already implemented)
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

func checkLoad() CheckResult {
	avg, err := load.Avg()
	if err != nil {
		return CheckResult{"load", Unknown, "load average unavailable", nil}
	}
	msg := fmt.Sprintf("1m=%.2f 5m=%.2f 15m=%.2f", avg.Load1, avg.Load5, avg.Load15)
	if avg.Load1 > 8 {
		return CheckResult{"load", Warning, msg, avg}
	}
	return CheckResult{"load", Healthy, msg, avg}
}

func checkProcesses() CheckResult {
	procs, err := process.Processes()
	if err != nil {
		return CheckResult{"processes", Unknown, "unable to list processes", nil}
	}
	count := len(procs)
	msg := fmt.Sprintf("%d processes", count)
	if count > 2000 {
		return CheckResult{"processes", Warning, msg, count}
	}
	return CheckResult{"processes", Healthy, msg, count}
}

func getLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}

	for _, iface := range ifaces {
		// Skip interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			// Skip link-local addresses (169.254.x.x)
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}

			return ip.String()
		}
	}

	return "127.0.0.1"
}
