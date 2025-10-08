package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/gosnmp/gosnmp"
)

type SNMPDeviceInfo struct {
	IP          string `json:"ip"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	OpenPorts   []int             `json:"open_ports,omitempty"`
	Health      map[string]string `json:"health,omitempty"`
}

// --- SNMP scanning (native) ---
// scanAndPollSNMPNative scans the provided IPv4 CIDR and attempts SNMP sysDescr GET on each host.
// concurrency controls parallel SNMP requests, timeout is per-request timeout.
func ScanAndPollSNMPNative(subnet, community string, concurrency int, timeout time.Duration) ([]SNMPDeviceInfo, int, error) {
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

func RunNmapScan(target, ports string, timeout time.Duration) ([]NmapScanResult, error) {
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
