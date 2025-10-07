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
	"context"

	"github.com/jackc/pgx/v5" 
	"github.com/jackc/pgx/v5/pgxpool"
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

const (
    green = "\033[32m"
    reset = "\033[0m"
)

var enableDB bool

const (
	dhost     = "localhost"
	port     = 5432
	user     = "postgres"
	password = ""
	dbname   = "goolag"
)

var db *pgxpool.Pool

func connectDB() {
    connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, password, dhost, port, dbname)

    var err error
    db, err = pgxpool.New(context.Background(), connStr)
    if err != nil {
        log.Printf("Unable to connect to database: %v", err)
        db = nil
        return
    }

    // Test connection
    err = db.Ping(context.Background())
    if err != nil {
        log.Printf("Unable to ping database: %v", err)
        db = nil
        return
    }

    log.Println("Connected to PostgreSQL")
}

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
	fmt.Print("Enable database logging? ([y/N] Only allow if you're host): ")
    var input string
    fmt.Scanln(&input)
    if input == "y" || input == "Y" || input == "yes" || input == "Yes" {
        enableDB = true
        connectDB()
        defer db.Close()
    } else {
        fmt.Println("Database logging disabled.")
    }

	refreshChecks()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
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

				var report HealthReport
				if err := json.Unmarshal(body, &report); err != nil {
					mu.Lock()
					results = append(results, Device{IP: ip, Err: "invalid JSON: " + err.Error()})
					mu.Unlock()
					return
				}

				// log.Println(report)

				go saveHealthReport(report)
				
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

	http.HandleFunc("/get_health_reports", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		hostname := r.URL.Query().Get("hostname")

		var rows pgx.Rows
		var err error

		ctx := context.Background()

		if hostname != "" {
			// Fetch last 10 rows for the given hostname (most recent first)
			query := `
				SELECT time, hostname, overall_status, os, platform, platform_version, kernel, uptime_seconds, checks
				FROM health_reports
				WHERE hostname = $1
				ORDER BY time DESC
				LIMIT 10
			`
			rows, err = db.Query(ctx, query, hostname)
		} else {
			// If no hostname provided, fetch last 10 from all hosts
			query := `
				SELECT time, hostname, overall_status, os, platform, platform_version, kernel, uptime_seconds, checks
				FROM health_reports
				ORDER BY time DESC
				LIMIT 10
			`
			rows, err = db.Query(ctx, query)
		}

		if err != nil {
			log.Printf("DB query error: %v", err)
			http.Error(w, "database query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type ReportRow struct {
			Time           time.Time           `json:"time"`
			Hostname       string              `json:"hostname"`
			OverallStatus  health.StatusLevel  `json:"overall_status"`
			OS             string              `json:"os"`
			Platform       string              `json:"platform"`
			PlatformVer    string              `json:"platform_version"`
			Kernel         string              `json:"kernel"`
			UptimeSeconds  uint64              `json:"uptime_seconds"`
			Checks         []health.CheckResult `json:"checks"`
		}

		reports := []ReportRow{}

		for rows.Next() {
			var (
				timeVal        time.Time
				hostnameVal    string
				overallStatus  health.StatusLevel
				osVal          string
				platformVal    string
				platformVerVal string
				kernelVal      string
				uptimeVal      uint64
				checksJSON     []byte
			)

			err := rows.Scan(&timeVal, &hostnameVal, &overallStatus, &osVal, &platformVal,
				&platformVerVal, &kernelVal, &uptimeVal, &checksJSON)
			if err != nil {
				log.Printf("DB scan error: %v", err)
				continue
			}

			var checks []health.CheckResult
			if err := json.Unmarshal(checksJSON, &checks); err != nil {
				log.Printf("JSON unmarshal error: %v", err)
			}

			reports = append(reports, ReportRow{
				Time:          timeVal,
				Hostname:      hostnameVal,
				OverallStatus: overallStatus,
				OS:            osVal,
				Platform:      platformVal,
				PlatformVer:   platformVerVal,
				Kernel:        kernelVal,
				UptimeSeconds: uptimeVal,
				Checks:        checks,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hostname": hostname,
			"count":    len(reports),
			"reports":  reports,
		})
	}))

	addr := ":8080"
	ip := getLocalIP()
	
	fmt.Println("\n" + green + "=== NMS Agent Endpoints ===" + reset + "\n")

    fmt.Println(green + "→ Metrics Endpoint:" + reset)
    fmt.Println("  http://" + ip + addr + "/metrics\n")

    fmt.Println(green + "→ SNMP Scan Endpoint:" + reset)
    fmt.Println("  http://" + ip + addr + "/snmp_scan?subnet=YOUR_SUBNET\n")

    fmt.Println(green + "→ NMAP Scan Endpoint:" + reset)
    fmt.Println("  http://" + ip + addr + "/nmap_scan?subnet=YOUR_SUBNET&ports=22,80,443&timeout=YOUR_TIME\n")

    fmt.Println(green + "→ Device Health Report Endpoint:" + reset)
    fmt.Println("  http://" + ip + addr + "/get_health_reports?hostname=DOMAIN_HOSTNAME\n")

    fmt.Println(green + "============================" + reset + "\n")
	log.Fatal(http.ListenAndServe(addr, nil));
}

func saveHealthReport(report HealthReport) {
	if !enableDB || db == nil {
        return
    }

    // if db == nil {
    //     log.Println("DB not connected")
    //     return
    // }

    checksJSON, err := json.Marshal(report.Checks)
    if err != nil {
        log.Printf("Error marshaling checks: %v", err)
        return
    }

    _, err = db.Exec(context.Background(),
        `INSERT INTO health_reports (time, hostname, overall_status, os, platform, platform_version, kernel, uptime_seconds, checks)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (time, hostname) DO NOTHING`,
        time.Now().UTC(),
        report.Hostname,
        report.OverallStatus,
        report.OS,
        report.Platform,
        report.PlatformVer,
        report.Kernel,
        report.UptimeSeconds,
        checksJSON,
    )

    if err != nil {
        log.Printf("Failed to insert health report: %v", err)
    }
}

func refreshChecks() {
	log.Println("refresh executed!")
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

	go saveHealthReport(report)
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
