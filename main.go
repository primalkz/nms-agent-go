package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"bytes"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"context"

	"github.com/gosnmp/gosnmp"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

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

// SNMPDeviceInfo describes the result for a scanned host
type SNMPDeviceInfo struct {
	IP          string `json:"ip"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	OpenPorts   []int             `json:"open_ports,omitempty"` // new field
	Health      map[string]string `json:"health,omitempty"`     // new health-related SNMP data
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

func expandCIDR(cidr string) ([]string, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }

    var ips []string
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
        ips = append(ips, ip.String())
    }

    // remove network and broadcast addresses
    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    return ips, nil
}

// incIP increments an IP address (used for iteration)
func incIP(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
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

	http.HandleFunc("/metrics", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		stateLock.RLock()
		defer stateLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}))

	http.HandleFunc("/snmp_scan", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			http.Error(w, "missing subnet parameter", http.StatusBadRequest)
			return
		}
		community := r.URL.Query().Get("community")
		if community == "" {
			community = "public"
		}
		concurrency := 50
		if v := r.URL.Query().Get("concurrency"); v != "" {
			if iv, err := strconv.Atoi(v); err == nil && iv > 0 {
				concurrency = iv
			}
		}
		timeout := 2 * time.Second
		if v := r.URL.Query().Get("timeout"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				timeout = d
			}
		}

		devices, failedCount, err := scanAndPollSNMPNative(subnet, community, concurrency, timeout)
		if err != nil {
			http.Error(w, "scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			Devices     []SNMPDeviceInfo `json:"devices"`
			FailedCount int              `json:"failed_count"`
		}{
			Devices:     devices,
			FailedCount: failedCount,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	http.HandleFunc("/nmap_scan", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			http.Error(w, "missing subnet parameter", http.StatusBadRequest)
			return
		}
		ports := r.URL.Query().Get("ports")
		if ports == "" {
			ports = "22,80,443"
		}
		timeout := 60 * time.Second
		if v := r.URL.Query().Get("timeout"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				timeout = d
			} else if iv, err := strconv.Atoi(v); err == nil {
				timeout = time.Duration(iv) * time.Second
			}
		}

		results, err := runNmapScan(subnet, ports, timeout)
		resp := struct {
			Results []NmapScanResult `json:"results"`
			Error   string           `json:"error,omitempty"`
		}{
			Results: results,
		}
		if err != nil {
			resp.Error = err.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// discover_agents?subnet=192.168.2.0/24&port=8080
	http.HandleFunc("/discover_agents", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			http.Error(w, "missing subnet param", http.StatusBadRequest)
			return
		}
		port := r.URL.Query().Get("port")
		if port == "" {
			port = "8080"
		}

		ips, err := expandCIDR(subnet)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		type Device struct {
			IP   string      `json:"ip"`
			Data interface{} `json:"data,omitempty"`
			Err  string      `json:"error,omitempty"`
		}

		results := []Device{}
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				url := fmt.Sprintf("http://%s:%s/metrics", ip, port)
				client := http.Client{ Timeout: 2 * time.Second }
				resp, err := client.Get(url)
				if err != nil {
					mu.Lock()
					results = append(results, Device{IP: ip, Err: err.Error()})
					mu.Unlock()
					return
				}
				defer resp.Body.Close()
				body, _ := ioutil.ReadAll(resp.Body)
				var data interface{}
				json.Unmarshal(body, &data)

				mu.Lock()
				results = append(results, Device{IP: ip, Data: data})
				mu.Unlock()
			}(ip)
		}

		wg.Wait()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"devices": results,
		})
	}))


	addr := ":8080"
	fmt.Println("NMS Agent running at http://" + getLocalIP() + addr + "/metrics")
	fmt.Println("SNMP scan endpoint: http://" + getLocalIP() + addr + "/snmp_scan?subnet=YOUR_SUBNET")
	fmt.Println("NMAP scan endpoint: http://" + getLocalIP() + addr + "/nmap_scan?subnet=YOUR_SUBNET&ports=22,80,443&timeout=YOUR_TIME")
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
	checks = append(checks, checkBattery())
	checks = append(checks, checkSystemInfo())

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

	// Linux-specific smartctl check
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

// checkBattery reports battery percentage. Uses platform-specific non-elevated methods:
// - Windows: wmic path Win32_Battery get EstimatedChargeRemaining
// - Linux: /sys/class/power_supply/*/capacity
// - Android: dumpsys battery OR getprop (dumpsys preferred)
func checkBattery() CheckResult {
	// Helper to decide status
	statusFromPct := func(p int) StatusLevel {
		if p < 0 {
			return Unknown
		}
		if p < 20 {
			return Critical
		}
		if p < 40 {
			return Warning
		}
		return Healthy
	}

	if runtime.GOOS == "windows" {
		out, err := exec.Command("wmic", "path", "Win32_Battery", "get", "EstimatedChargeRemaining").Output()
		if err != nil {
			// wmic might not exist or battery not present
			return CheckResult{"battery", Unknown, "wmic query failed or no battery present", nil}
		}
		lines := strings.Fields(string(out))
		// Expect header + value(s). Find first integer value
		for _, tok := range lines {
			if n, err := strconv.Atoi(tok); err == nil {
				status := statusFromPct(n)
				return CheckResult{"battery", status, fmt.Sprintf("battery %d%%", n), map[string]int{"percentage": n}}
			}
		}
		return CheckResult{"battery", Unknown, "no battery info found", nil}
	}

	// Android: try dumpsys battery then getprop fallback
	if runtime.GOOS == "android" {
		// dumpsys battery (preferred)
		if out, err := exec.Command("dumpsys", "battery").Output(); err == nil {
			// look for "level: <n>"
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "level:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if n, err := strconv.Atoi(parts[1]); err == nil {
							status := statusFromPct(n)
							return CheckResult{"battery", status, fmt.Sprintf("battery %d%%", n), map[string]int{"percentage": n}}
						}
					}
				}
			}
		}
		// fallback: getprop ro.battery... (less common) or fail
		if out, err := exec.Command("getprop", "ro.boot.battery").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				if n, err := strconv.Atoi(s); err == nil {
					return CheckResult{"battery", statusFromPct(n), fmt.Sprintf("battery %d%%", n), map[string]int{"percentage": n}}
				}
			}
		}
		return CheckResult{"battery", Unknown, "cannot determine battery on android", nil}
	}

	// Generic Linux / other Unix: check /sys/class/power_supply/*
	// This avoids elevated permissions; reading those files is generally permitted.
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" {
		// look for any capacity file under /sys/class/power_supply
		paths, _ := ioutil.ReadDir("/sys/class/power_supply")
		for _, p := range paths {
			capPath := "/sys/class/power_supply/" + p.Name() + "/capacity"
			if data, err := ioutil.ReadFile(capPath); err == nil {
				s := strings.TrimSpace(string(data))
				if n, err := strconv.Atoi(s); err == nil {
					status := statusFromPct(n)
					return CheckResult{"battery", status, fmt.Sprintf("%s battery %d%%", p.Name(), n), map[string]int{"percentage": n}}
				}
			}
			// Some systems use "charge_now"/"charge_full" to compute percent; try those if capacity unavailable
			chargeNow := "/sys/class/power_supply/" + p.Name() + "/charge_now"
			chargeFull := "/sys/class/power_supply/" + p.Name() + "/charge_full"
			if dn, err1 := ioutil.ReadFile(chargeNow); err1 == nil {
				if df, err2 := ioutil.ReadFile(chargeFull); err2 == nil {
					if n1, err3 := strconv.Atoi(strings.TrimSpace(string(dn))); err3 == nil {
						if n2, err4 := strconv.Atoi(strings.TrimSpace(string(df))); err4 == nil && n2 > 0 {
							percent := int(float64(n1) / float64(n2) * 100.0)
							status := statusFromPct(percent)
							return CheckResult{"battery", status, fmt.Sprintf("%s battery %d%% (calc)", p.Name(), percent), map[string]int{"percentage": percent}}
						}
					}
				}
			}
		}
		// If no battery entries found, it's likely a server or no battery
		return CheckResult{"battery", Unknown, "no battery information found", nil}
	}

	// fallback for unknown OSes
	return CheckResult{"battery", Unknown, "battery check not implemented for this OS", nil}
}

// checkSystemInfo gathers system vendor/make, model and serial number using non-elevated means:
// - Windows: wmic csproduct / wmic bios get serialnumber
// - Linux: /sys/class/dmi/id/* or hostnamectl fallback, /proc/cpuinfo (Raspberry Pi's "Serial")
// - Android: getprop ro.product.manufacturer / ro.product.model / ro.serialno or ro.boot.serialno
func checkSystemInfo() CheckResult {
	info := map[string]string{
		"vendor": "",
		"model":  "",
		"serial": "",
	}

	if runtime.GOOS == "windows" {
		// vendor/model
		if out, err := exec.Command("wmic", "csproduct", "get", "vendor,version,name", "/format:list").Output(); err == nil {
			// parse lines like Vendor=Dell Inc.
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				kv := strings.SplitN(line, "=", 2)
				if len(kv) != 2 {
					continue
				}
				k := strings.ToLower(strings.TrimSpace(kv[0]))
				v := strings.TrimSpace(kv[1])
				switch k {
				case "vendor":
					info["vendor"] = v
				case "name":
					// name often contains model/product
					info["model"] = v
				}
			}
		}
		// serial: BIOS serial
		if out, err := exec.Command("wmic", "bios", "get", "serialnumber").Output(); err == nil {
			lines := strings.Fields(string(out))
			// first numeric/text token after header
			for _, tok := range lines {
				// skip header "SerialNumber"
				if strings.EqualFold(tok, "SerialNumber") {
					continue
				}
				// take first remaining token
				info["serial"] = tok
				break
			}
		}
		// Finalize
		if info["vendor"] == "" && info["model"] == "" && info["serial"] == "" {
			return CheckResult{"system_info", Unknown, "wmic queries failed or no info", info}
		}
		return CheckResult{"system_info", Healthy, "system info collected (windows)", info}
	}

	if runtime.GOOS == "android" {
		// getprop is commonly available on Android devices
		for k, prop := range map[string]string{"vendor": "ro.product.manufacturer", "model": "ro.product.model", "serial": "ro.serialno"} {
			if out, err := exec.Command("getprop", prop).Output(); err == nil {
				val := strings.TrimSpace(string(out))
				if val != "" && val != "unknown" {
					info[k] = val
				}
			}
		}
		// fallback for serial
		if info["serial"] == "" {
			if out, err := exec.Command("getprop", "ro.boot.serialno").Output(); err == nil {
				if s := strings.TrimSpace(string(out)); s != "" {
					info["serial"] = s
				}
			}
		}
		if info["vendor"] == "" && info["model"] == "" && info["serial"] == "" {
			return CheckResult{"system_info", Unknown, "getprop failed to return system info", info}
		}
		return CheckResult{"system_info", Healthy, "system info collected (android)", info}
	}

	// Linux and other Unix-like
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" {
		// Try sysfs/dmi entries (commonly readable)
		tryRead := func(path string) string {
			if data, err := ioutil.ReadFile(path); err == nil {
				return strings.TrimSpace(string(data))
			}
			return ""
		}
		if v := tryRead("/sys/class/dmi/id/sys_vendor"); v != "" {
			info["vendor"] = v
		}
		if v := tryRead("/sys/class/dmi/id/product_name"); v != "" {
			info["model"] = v
		}
		if v := tryRead("/sys/class/dmi/id/product_serial"); v != "" {
			info["serial"] = v
		}
		// Other possible fields
		if info["serial"] == "" {
			if v := tryRead("/sys/class/dmi/id/board_serial"); v != "" {
				info["serial"] = v
			}
		}
		// hostnamectl fallback (may include "Machine ID" or vendor/product lines)
		if info["vendor"] == "" || info["model"] == "" {
			if out, err := exec.Command("hostnamectl").Output(); err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(strings.ToLower(line), "chassis:") {
						// ignore
					}
					if strings.HasPrefix(strings.ToLower(line), "vendor:") && info["vendor"] == "" {
						info["vendor"] = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					}
					if strings.HasPrefix(strings.ToLower(line), "model:") && info["model"] == "" {
						info["model"] = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					}
				}
			}
		}
		// Raspberry Pi / ARM boards often put serial in /proc/cpuinfo
		if info["serial"] == "" {
			if out, err := ioutil.ReadFile("/proc/cpuinfo"); err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(strings.ToLower(line), "serial") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							if s := strings.TrimSpace(parts[1]); s != "" {
								info["serial"] = s
								break
							}
						}
					}
				}
			}
		}

		// If still nothing, mark unknown
		if info["vendor"] == "" && info["model"] == "" && info["serial"] == "" {
			return CheckResult{"system_info", Unknown, "no system DMI info available (requires /sys/class/dmi/id or hostnamectl)", info}
		}
		return CheckResult{"system_info", Healthy, "system info collected (linux)", info}
	}

	return CheckResult{"system_info", Unknown, "system info check not implemented for this OS", info}
}

// --- SNMP scanning (native) ---

// scanAndPollSNMPNative scans the provided IPv4 CIDR and attempts SNMP sysDescr GET on each host.
// concurrency controls parallel SNMP requests, timeout is per-request timeout.
func scanAndPollSNMPNative(subnet, community string, concurrency int, timeout time.Duration) ([]SNMPDeviceInfo, int, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, 0, err
	}

	ips := ipsInNet(ipnet)
	if len(ips) == 0 {
		return nil, 0, errors.New("no hosts in subnet")
	}

	sem := make(chan struct{}, concurrency)
	results := make(chan *SNMPDeviceInfo, len(ips))
	errorsCount := 0
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			// SNMP sysDescr
			desc, err := snmpGetSysDescrWithParams(ip, community, timeout)
			if err != nil {
				results <- nil
				return
			}
			// sysObjectID
			sysObjectID, err := snmpGetWithOID(ip, community, timeout, ".1.3.6.1.2.1.1.2.0")
			if err != nil {
				sysObjectID = ""
			}
			// sysName
			sysName, err := snmpGetWithOID(ip, community, timeout, ".1.3.6.1.2.1.1.5.0")
			if err != nil {
				sysName = ""
			}

			// Get additional SNMP health info (example OIDs)
			healthData := map[string]string{}

			// Example: CPU load 1 min average
			if cpuLoad, err := snmpGetWithOID(ip, community, timeout, ".1.3.6.1.4.1.2021.10.1.3.1"); err == nil {
				healthData["cpu_load_1min"] = cpuLoad
			}
			// Example: Available memory in kB
			if memAvail, err := snmpGetWithOID(ip, community, timeout, ".1.3.6.1.4.1.2021.4.6.0"); err == nil {
				healthData["mem_avail_kb"] = memAvail
			}
			// Example: Total memory in kB
			if memTotal, err := snmpGetWithOID(ip, community, timeout, ".1.3.6.1.4.1.2021.4.5.0"); err == nil {
				healthData["mem_total_kb"] = memTotal
			}

			// Run Nmap port scan (e.g., top 100 ports)
			openPorts, err := nmapPortScan(ip)
			if err != nil {
				// On error, just return empty open ports slice, don't fail whole scan
				openPorts = []int{}
			}

			results <- &SNMPDeviceInfo{
				IP:          ip,
				SysDescr:    desc,
				SysObjectID: sysObjectID,
				SysName:     sysName,
				OpenPorts:   openPorts,
				Health:      healthData,
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	var devices []SNMPDeviceInfo
	for res := range results {
		if res == nil {
			errorsCount++
			continue
		}
		devices = append(devices, *res)
	}
	return devices, errorsCount, nil
}

func ipsInNetMust(subnet string) []string {
    _, ipnet, err := net.ParseCIDR(subnet)
    if err != nil {
        // You can decide whether to panic or just return empty slice
        panic("invalid subnet CIDR: " + err.Error())
    }
    return ipsInNet(ipnet)
}

type NmapScanResult struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"open_ports"`
	Error     string `json:"error,omitempty"`
}

func runNmapScan(target, ports string, timeout time.Duration) ([]NmapScanResult, error) {
	// Build command: nmap -p <ports> --open -T4 -oG - <target>
	// --open ensures grepable output only lists open ports, but output still contains Ports: fields
	args := []string{"-p", ports, "--open", "-T4", "-oG", "-", target}

	// Run with context to allow timeout/cancel
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If context timed out, return that info; still try to parse whatever output exists
		if ctx.Err() == context.DeadlineExceeded {
			// Try to parse partial output if any
			results := parseNmapGrepOutput(out)
			return results, fmt.Errorf("nmap timed out after %s; parsed partial results (%d hosts)", timeout, len(results))
		}
		// other errors: return parse attempt too
		results := parseNmapGrepOutput(out)
		return results, fmt.Errorf("nmap error: %v; parsed partial results (%d hosts). stderr/stdout:\n%s", err, len(results), string(out))
	}

	results := parseNmapGrepOutput(out)
	return results, nil
}

func parseNmapGrepOutput(output []byte) []NmapScanResult {
	var results []NmapScanResult
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		// we only care lines that start with "Host:" (grepable format)
		if !bytes.HasPrefix(line, []byte("Host:")) {
			continue
		}

		// Example line format: Host: 192.168.2.1 ()\tStatus: Up
		// or: Host: 192.168.2.1 ()\tPorts: 22/open/tcp//ssh///,80/open/tcp//http///  Ignored State: closed (997)
		parts := bytes.SplitN(line, []byte("\t"), 3)
		if len(parts) < 2 {
			continue
		}

		// extract IP from "Host: <ip> (..)"
		hostField := string(parts[0]) // "Host: 192.168.2.1 ()"
		hostParts := strings.Fields(hostField)
		ip := ""
		if len(hostParts) >= 2 {
			ip = hostParts[1]
		}
		if ip == "" {
			continue
		}

		openPorts := []int{}
		// look for "Ports:" segment among parts
		for _, p := range parts {
			if bytes.Contains(p, []byte("Ports:")) {
				idx := bytes.Index(p, []byte("Ports:"))
				portsPart := p[idx+len("Ports:"):]
				// ports are comma-separated entries like "22/open/tcp//ssh///"
				portsList := bytes.Split(portsPart, []byte(","))
				for _, entry := range portsList {
					entry = bytes.TrimSpace(entry)
					if len(entry) == 0 {
						continue
					}
					fields := bytes.Split(entry, []byte("/"))
					if len(fields) >= 2 {
						portStr := string(fields[0])
						state := string(fields[1])
						if state == "open" {
							if pn, err := strconv.Atoi(portStr); err == nil {
								openPorts = append(openPorts, pn)
							}
						}
					}
				}
				break
			}
		}

		results = append(results, NmapScanResult{
			IP:        ip,
			OpenPorts: openPorts,
		})
	}
	return results
}

// Helper function to run nmap with ports on a single IP
func runNmapForIP(ip, ports string) ([]int, error) {
    cmd := exec.Command("nmap", "-p", ports, "--open", "-T4", "-oG", "-", ip)
    out, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    lines := bytes.Split(out, []byte("\n"))
    for _, line := range lines {
        if !bytes.Contains(line, []byte("Ports:")) {
            continue
        }
        parts := bytes.Split(line, []byte("Ports:"))
        if len(parts) < 2 {
            continue
        }
        portsPart := parts[1]
        portsList := bytes.Split(portsPart, []byte(","))
        openPorts := []int{}
        for _, p := range portsList {
            fields := bytes.Split(p, []byte("/"))
            if len(fields) < 2 {
                continue
            }
            portStr := string(fields[0])
            state := string(fields[1])
            if state == "open" {
                if portNum, err := strconv.Atoi(portStr); err == nil {
                    openPorts = append(openPorts, portNum)
                }
            }
        }
        return openPorts, nil
    }
    return []int{}, nil
}

// nmapPortScan runs a basic nmap scan on given IP and returns open TCP ports
func nmapPortScan(ip string) ([]int, error) {
	// Use nmap -p- --min-rate=500 --open -T4 to scan all TCP ports quickly for open ports
	// For faster scan, limit to top 100 ports: nmap --top-ports 100 --open
	// Modify command line as you wish

	cmd := exec.Command("nmap", "--top-ports", "100", "--open", "-T4", "-oG", "-", ip)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// Parse output looking for "Ports:" line in grepable output
	// Example line:
	// Host: 192.168.1.1 ()	Status: Up
	// Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh///,80/open/tcp//http///,443/open/tcp//https/// Ignored State: closed (997)

	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		if !bytes.Contains(line, []byte("Ports:")) {
			continue
		}
		parts := bytes.Split(line, []byte("Ports:"))
		if len(parts) < 2 {
			continue
		}
		portsPart := parts[1]
		// ports are comma separated: 22/open/tcp//ssh///,80/open/tcp//http///
		portsList := bytes.Split(portsPart, []byte(","))
		openPorts := []int{}
		for _, p := range portsList {
			fields := bytes.Split(p, []byte("/"))
			if len(fields) < 2 {
				continue
			}
			portStr := string(fields[0])
			state := string(fields[1])
			if state == "open" {
				if portNum, err := strconv.Atoi(portStr); err == nil {
					openPorts = append(openPorts, portNum)
				}
			}
		}
		return openPorts, nil
	}
	return []int{}, nil
}


// Helper for single OID get as string
func snmpGetWithOID(ip, community string, timeout time.Duration, oid string) (string, error) {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	if err := params.Connect(); err != nil {
		return "", err
	}
	defer params.Conn.Close()

	resp, err := params.Get([]string{oid})
	if err != nil {
		return "", err
	}
	if resp == nil || len(resp.Variables) == 0 {
		return "", errors.New("no SNMP response")
	}
	pdu := resp.Variables[0]
	if pdu.Type == gosnmp.OctetString {
		if b, ok := pdu.Value.([]byte); ok {
			return string(b), nil
		}
	}
	return fmt.Sprint(pdu.Value), nil
}

// ipsInNet returns host IPv4 addresses in the network, skipping network and broadcast addresses.
func ipsInNet(ipnet *net.IPNet) []string {
	var ips []string

	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return ips
	}

	// compute uint32 values
	toUint32 := func(ip net.IP) uint32 {
		b := ip.To4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	fromUint32 := func(n uint32) net.IP {
		return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
	}

	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return ips
	}

	network := toUint32(ip4) & toUint32(mask)
	broadcast := network | ^toUint32(mask)

	// if /31 or /32 there are no usable hosts (handle /32 separately)
	ones, bits := ipnet.Mask.Size()
	if bits-ones <= 0 {
		// single host (/32)
		if ones == bits {
			return []string{ipnet.IP.String()}
		}
		return ips
	}

	for n := network + 1; n < broadcast; n++ {
		ips = append(ips, fromUint32(n).String())
	}
	return ips
}

// snmpGetSysDescrWithParams performs SNMP GET (.1.3.6.1.2.1.1.1.0) on ip using given community and timeout.
func snmpGetSysDescrWithParams(ip, community string, timeout time.Duration) (string, error) {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	if err := params.Connect(); err != nil {
		return "", err
	}
	defer params.Conn.Close()

	oids := []string{".1.3.6.1.2.1.1.1.0"}
	resp, err := params.Get(oids)
	if err != nil {
		return "", err
	}
	if resp == nil || len(resp.Variables) == 0 {
		return "", errors.New("no SNMP response")
	}
	pdu := resp.Variables[0]
	if pdu.Type == gosnmp.OctetString {
		if b, ok := pdu.Value.([]byte); ok {
			return string(b), nil
		}
	}
	return fmt.Sprint(pdu.Value), nil
}

// --- Utility: improved local IP detection ---

func getLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}

	for _, iface := range ifaces {
		// skip down or loopback interfaces
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
				continue // not ipv4
			}
			// skip link-local 169.254.x.x
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}
			return ip.String()
		}
	}
	return "127.0.0.1"
}
