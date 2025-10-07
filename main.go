package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"log"

	"github.com/shirou/gopsutil/v4/host"

	"nms_agent_go/health"
	"nms_agent_go/network"
)

const (
    Critical = health.Critical
    Warning  = health.Warning
    Healthy  = health.Healthy
    Unknown  = health.Unknown
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

type HealthReport struct {
	Hostname      string        `json:"hostname"`
	OS            string        `json:"os"`
	Platform      string        `json:"platform"`
	PlatformVer   string        `json:"platform_version"`
	Kernel        string        `json:"kernel"`
	OverallStatus health.StatusLevel   `json:"overall_status"`
	UptimeSeconds uint64        `json:"uptime_seconds"`
	Checks        []health.CheckResult `json:"checks"`
}

var (
	state     HealthReport
	stateLock sync.RWMutex
)

func worst(a, b health.StatusLevel) health.StatusLevel {
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

    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    return ips, nil
}

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

		devices, failedCount, err := network.ScanAndPollSNMPNative(subnet, community, concurrency, timeout)
		if err != nil {
			http.Error(w, "scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			Devices     []network.SNMPDeviceInfo `json:"devices"`
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

		results, err := network.RunNmapScan(subnet, ports, timeout)
		resp := struct {
			Results []network.NmapScanResult `json:"results"`
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
	log.Fatal(http.ListenAndServe(addr, nil));
}

func refreshChecks() {
	var checks []health.CheckResult

	hostname, _ := os.Hostname()
	uptime, _ := host.Uptime()
	info, _ := host.Info()

	checks = append(checks, health.CheckCPU())
    checks = append(checks, health.CheckMemory())
    checks = append(checks, health.CheckDisks())
    checks = append(checks, health.CheckNetwork())
    checks = append(checks, health.CheckSmart())
    checks = append(checks, health.CheckMdRaid())
    checks = append(checks, health.CheckIPMI())
    checks = append(checks, health.CheckLoad())
    checks = append(checks, health.CheckProcesses())
    checks = append(checks, health.CheckBattery())
    checks = append(checks, health.CheckSystemInfo())

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
