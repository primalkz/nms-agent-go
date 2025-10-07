package health


import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
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

// --- Checks ---

func CheckCPU() CheckResult {
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

func CheckMemory() CheckResult {
	vm, _ := mem.VirtualMemory()
	percent := vm.UsedPercent
	if percent > 90 {
		return CheckResult{"memory", Critical, fmt.Sprintf("memory high: %.1f%%", percent), nil}
	} else if percent > 75 {
		return CheckResult{"memory", Warning, fmt.Sprintf("memory elevated: %.1f%%", percent), nil}
	}
	return CheckResult{"memory", Healthy, fmt.Sprintf("memory ok: %.1f%%", percent), nil}
}

func CheckDisks() CheckResult {
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

func CheckNetwork() CheckResult {
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

func CheckSmart() CheckResult {
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

func CheckMdRaid() CheckResult {
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

func CheckIPMI() CheckResult {
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

func CheckLoad() CheckResult {
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

func CheckProcesses() CheckResult {
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
func CheckBattery() CheckResult {
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
		out, err := exec.Command("wmic", "path", "Win32_Battery", "get", "EstimatedChargeRemaining,BatteryStatus", "/format:list").Output()
		if err != nil {
			return CheckResult{"battery", Unknown, "wmic query failed or no battery present", nil}
		}

		lines := strings.Split(string(out), "\n")
		var percentage int = -1
		var batteryStatus int = -1

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "EstimatedChargeRemaining=") {
				value := strings.TrimPrefix(line, "EstimatedChargeRemaining=")
				if n, err := strconv.Atoi(value); err == nil {
					percentage = n
				}
			} else if strings.HasPrefix(line, "BatteryStatus=") {
				value := strings.TrimPrefix(line, "BatteryStatus=")
				if n, err := strconv.Atoi(value); err == nil {
					batteryStatus = n
				}
			}
		}

		charging := batteryStatus == 6 || batteryStatus == 7 || batteryStatus == 8 || batteryStatus == 9 || batteryStatus == 2

		var status StatusLevel
		if charging {
			status = Healthy
		} else {
			status = statusFromPct(percentage)
		}

		msg := fmt.Sprintf("battery %d%%", percentage)
		if charging {
			msg += " (charging)"
		}

		return CheckResult{
			Name:    "battery",
			Status:  status,
			Message: msg,
			Details: map[string]interface{}{
				"percentage":    percentage,
				"charging":      charging,
				"batteryStatus": batteryStatus,
			},
		}
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
		entries, _ := ioutil.ReadDir("/sys/class/power_supply")
		for _, entry := range entries {
			basePath := "/sys/class/power_supply/" + entry.Name()

			// Check if this is a battery
			typePath := basePath + "/type"
			if data, err := ioutil.ReadFile(typePath); err == nil {
				deviceType := strings.TrimSpace(string(data))
				if deviceType != "Battery" {
					continue // skip non-battery devices like AC
				}
			} else {
				continue // skip if no type
			}

			// Read percentage from 'capacity'
			capPath := basePath + "/capacity"
			var percent int = -1
			if data, err := ioutil.ReadFile(capPath); err == nil {
				if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
					percent = n
				}
			}

			// Try to calculate percentage manually if not found
			if percent < 0 {
				chargeNow := basePath + "/charge_now"
				chargeFull := basePath + "/charge_full"
				if dn, err1 := ioutil.ReadFile(chargeNow); err1 == nil {
					if df, err2 := ioutil.ReadFile(chargeFull); err2 == nil {
						if n1, err3 := strconv.Atoi(strings.TrimSpace(string(dn))); err3 == nil {
							if n2, err4 := strconv.Atoi(strings.TrimSpace(string(df))); err4 == nil && n2 > 0 {
								percent = int(float64(n1) / float64(n2) * 100.0)
							}
						}
					}
				}
			}

			// Read charging status
			charging := false
			statusPath := basePath + "/status"
			if data, err := ioutil.ReadFile(statusPath); err == nil {
				s := strings.TrimSpace(string(data))
				if s == "Charging" || s == "Full" {
					charging = true
				}
			}

			// Determine health
			var status StatusLevel
			if charging {
				status = Healthy
			} else {
				status = statusFromPct(percent)
			}

			msg := fmt.Sprintf("%s battery %d%%", entry.Name(), percent)
			if charging {
				msg += " (charging)"
			}

			return CheckResult{
				Name:    "battery",
				Status:  status,
				Message: msg,
				Details: map[string]interface{}{
					"percentage": percent,
					"charging":   charging,
					"device":     entry.Name(),
				},
			}
		}

		return CheckResult{"battery", Unknown, "no battery information found", nil}
	}



	// fallback for unknown OSes
	return CheckResult{"battery", Unknown, "battery check not implemented for this OS", nil}
}

// checkSystemInfo gathers system vendor/make, model and serial number using non-elevated means:
// - Windows: wmic csproduct / wmic bios get serialnumber
// - Linux: /sys/class/dmi/id/* or hostnamectl fallback, /proc/cpuinfo (Raspberry Pi's "Serial")
// - Android: getprop ro.product.manufacturer / ro.product.model / ro.serialno or ro.boot.serialno
func CheckSystemInfo() CheckResult {
	info := map[string]string{
		"vendor":  "",
		"model":   "",
		"serial":  "",
		"username": "",
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

		// get username
		if out, err := exec.Command("whoami").Output(); err == nil {
			username := strings.TrimSpace(string(out))
			parts := strings.Split(username, "\\")
			if len(parts) > 1 {
				info["username"] = parts[1] // Only take the part after the backslash
			} else {
				info["username"] = username // If there is no backslash, just use the whole string
			}
		}

		// Finalize
		if info["vendor"] == "" && info["model"] == "" && info["serial"] == "" && info["username"] == "" {
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

		// get username for linux
		if username := os.Getenv("USER"); username != "" {
			info["username"] = username
		}

		// If still nothing, mark unknown
		if info["vendor"] == "" && info["model"] == "" && info["serial"] == "" && info["username"] == "" {
			return CheckResult{"system_info", Unknown, "no system DMI info available (requires /sys/class/dmi/id or hostnamectl)", info}
		}
		return CheckResult{"system_info", Healthy, "system info collected (linux)", info}
	}

	return CheckResult{"system_info", Unknown, "system info check not implemented for this OS", info}
}