package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult represents the result of a port scan
type ScanResult struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Protocol string `json:"protocol"`
}

// Scanner holds the scanner configuration and state
type Scanner struct {
	host        string
	timeout     time.Duration
	concurrency int
	protocol    string
	scanType    string
	ports       []int
	results     []ScanResult
	mu          sync.Mutex
}

// NewScanner creates a new scanner instance
func NewScanner(host string, timeout time.Duration, concurrency int, protocol string, scanType string) *Scanner {
	return &Scanner{
		host:        host,
		timeout:     timeout,
		concurrency: concurrency,
		protocol:    protocol,
		scanType:    scanType,
		results:     make([]ScanResult, 0),
	}
}

// TCPConnectScan performs a TCP connect scan
func (s *Scanner) TCPConnectScan(port int) ScanResult {
	address := fmt.Sprintf("%s:%d", s.host, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	
	result := ScanResult{
		Port:     port,
		Protocol: "tcp",
	}
	
	if err != nil {
		result.State = "closed"
		return result
	}
	defer conn.Close()
	
	result.State = "open"
	
	// Try to grab banner
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	banner := make([]byte, 1024)
	n, _ := conn.Read(banner)
	if n > 0 {
		result.Banner = strings.TrimSpace(string(banner[:n]))
	}
	
	// Detect service based on port
	result.Service = detectService(port)
	
	return result
}

// UDPScan performs a UDP scan
func (s *Scanner) UDPScan(port int) ScanResult {
	address := fmt.Sprintf("%s:%d", s.host, port)
	conn, err := net.DialTimeout("udp", address, s.timeout)
	
	result := ScanResult{
		Port:     port,
		Protocol: "udp",
	}
	
	if err != nil {
		result.State = "closed"
		return result
	}
	defer conn.Close()
	
	// Send a simple probe
	conn.SetDeadline(time.Now().Add(s.timeout))
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		result.State = "closed"
		return result
	}
	
	// Try to read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// UDP is connectionless, so no response doesn't necessarily mean closed
		// For simplicity, we'll mark it as open|filtered
		result.State = "open|filtered"
	} else {
		result.State = "open"
		if n > 0 {
			result.Banner = strings.TrimSpace(string(buffer[:n]))
		}
	}
	
	// Detect service based on port
	result.Service = detectService(port)
	
	return result
}

// detectService attempts to identify the service running on a port
func detectService(port int) string {
	commonPorts := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		67:    "dhcp",
		68:    "dhcp",
		69:    "tftp",
		80:    "http",
		110:   "pop3",
		123:   "ntp",
		135:   "msrpc",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		139:   "netbios-ssn",
		143:   "imap",
		161:   "snmp",
		162:   "snmp-trap",
		179:   "bgp",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		500:   "isakmp",
		514:   "syslog",
		515:   "printer",
		587:   "smtp-submission",
		631:   "ipp",
		636:   "ldaps",
		993:   "imaps",
		995:   "pop3s",
		1080:  "socks",
		1194:  "openvpn",
		1433:  "ms-sql-s",
		1521:  "oracle",
		1723:  "pptp",
		1883:  "mqtt",
		1900:  "upnp",
		2049:  "nfs",
		2082:  "cpanel",
		2083:  "cpanel-ssl",
		2086:  "whm",
		2087:  "whm-ssl",
		2095:  "webmail",
		2096:  "webmail-ssl",
		2181:  "zookeeper",
		2375:  "docker",
		2376:  "docker-ssl",
		3000:  "nodejs",
		3306:  "mysql",
		3389:  "rdp",
		3690:  "svn",
		4333:  "ahsp",
		4369:  "epmd",
		4443:  "phppgadmin",
		4505:  "salt-master",
		4506:  "salt-api",
		4789:  "vxlan",
		4848:  "appserver-https",
		4900:  "matahari",
		5000:  "upnp",
		5432:  "postgresql",
		5601:  "kibana",
		5672:  "amqp",
		5900:  "vnc",
		5938:  "teamviewer",
		5984:  "couchdb",
		6000:  "x11",
		6379:  "redis",
		6443:  "kubernetes-api",
		6666:  "irc",
		6667:  "irc",
		6668:  "irc",
		6669:  "irc",
		8000:  "http-alt",
		8008:  "http-alt",
		8080:  "http-proxy",
		8081:  "http-alt",
		8443:  "https-alt",
		8888:  "http-alt",
		9000:  "http-alt",
		9001:  "http-alt",
		9042:  "cassandra",
		9092:  "kafka",
		9100:  "jetdirect",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		9418:  "git",
		9999:  "http-alt",
		10000: "webmin",
		11211: "memcached",
		15672: "rabbitmq",
		27017: "mongodb",
		27018: "mongodb",
		28017: "mongodb",
		32400: "plex",
		49152: "unknown",
		49153: "unknown",
		49154: "unknown",
		49155: "unknown",
		49156: "unknown",
		49157: "unknown",
	}
	
	if service, ok := commonPorts[port]; ok {
		return service
	}
	return "unknown"
}

// ScanPorts scans a range of ports
func (s *Scanner) ScanPorts(startPort, endPort int) {
	ports := make(chan int, s.concurrency)
	results := make(chan ScanResult, endPort-startPort+1)
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				var result ScanResult
				switch s.scanType {
				case "tcp":
					result = s.TCPConnectScan(port)
				case "udp":
					result = s.UDPScan(port)
				default:
					result = s.TCPConnectScan(port)
				}
				results <- result
			}
		}()
	}
	
	// Send ports to workers
	go func() {
		for port := startPort; port <= endPort; port++ {
			ports <- port
		}
		close(ports)
	}()
	
	// Wait for all workers to finish
	wg.Wait()
	close(results)
	
	// Collect results
	for result := range results {
		s.mu.Lock()
		if result.State == "open" || result.State == "open|filtered" {
			s.results = append(s.results, result)
		}
		s.mu.Unlock()
	}
	
	// Sort results by port number
	sort.Slice(s.results, func(i, j int) bool {
		return s.results[i].Port < s.results[j].Port
	})
}

// PrintResults prints scan results in the specified format
func (s *Scanner) PrintResults(format string) {
	switch format {
	case "json":
		jsonOutput, _ := json.MarshalIndent(s.results, "", "  ")
		fmt.Println(string(jsonOutput))
	case "simple":
		for _, result := range s.results {
			fmt.Printf("Port %d/%s %s", result.Port, result.Protocol, result.State)
			if result.Service != "" && result.Service != "unknown" {
				fmt.Printf(" (%s)", result.Service)
			}
			fmt.Println()
		}
	case "verbose":
		fmt.Printf("Scan report for %s\n", s.host)
		fmt.Println("PORT     STATE SERVICE")
		for _, result := range s.results {
			service := result.Service
			if service == "unknown" {
				service = ""
			}
			fmt.Printf("%d/%s %s %s\n", result.Port, result.Protocol, result.State, service)
			if result.Banner != "" {
				fmt.Printf("  Banner: %s\n", result.Banner)
			}
		}
		fmt.Printf("\nScanned %d ports\n", len(s.results))
	default:
		// Default to nmap-like format
		fmt.Printf("Starting Nmap-like port scanner at %s\n", time.Now().Format("2006-01-02 15:04"))
		fmt.Printf("Scanning %s\n", s.host)
		fmt.Println("PORT     STATE SERVICE")
		for _, result := range s.results {
			service := result.Service
			if service == "unknown" {
				service = ""
			}
			fmt.Printf("%d/%s %s %s\n", result.Port, result.Protocol, result.State, service)
		}
		fmt.Printf("\nNmap-like scan completed: %d open ports\n", len(s.results))
	}
}

// parsePortRange parses a port range string like "1-100" or "80,443,8080"
func parsePortRange(portRange string) ([]int, error) {
	var ports []int
	
	// Check if it's a single port
	if !strings.Contains(portRange, "-") && !strings.Contains(portRange, ",") {
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portRange)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		return []int{port}, nil
	}
	
	// Check if it's a range
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", portRange)
		}
		
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %s", parts[0])
		}
		
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %s", parts[1])
		}
		
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return nil, fmt.Errorf("port range %d-%d out of range (1-65535)", start, end)
		}
		
		if start > end {
			start, end = end, start
		}
		
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
		return ports, nil
	}
	
	// Check if it's a comma-separated list
	if strings.Contains(portRange, ",") {
		parts := strings.Split(portRange, ",")
		for _, part := range parts {
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d out of range (1-65535)", port)
			}
			ports = append(ports, port)
		}
		return ports, nil
	}
	
	return nil, fmt.Errorf("invalid port specification: %s", portRange)
}

func main() {
	var (
		host        string
		portRange   string
		timeoutSec  int
		concurrency int
		scanType    string
		outputFormat string
	)
	
	flag.StringVar(&host, "host", "", "Target host to scan")
	flag.StringVar(&portRange, "ports", "1-1000", "Ports to scan (e.g., 1-1000, 80,443,8080)")
	flag.IntVar(&timeoutSec, "timeout", 2, "Timeout in seconds for each connection")
	flag.IntVar(&concurrency, "concurrency", 100, "Number of concurrent scans")
	flag.StringVar(&scanType, "scan-type", "tcp", "Scan type (tcp, syn, udp)")
	flag.StringVar(&outputFormat, "output", "nmap", "Output format (nmap, simple, verbose, json)")
	
	flag.Parse()
	
	if host == "" {
		fmt.Println("Error: host is required")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	// Parse port range
	ports, err := parsePortRange(portRange)
	if err != nil {
		fmt.Printf("Error parsing port range: %v\n", err)
		os.Exit(1)
	}
	
	// Create scanner
	scanner := NewScanner(
		host,
		time.Duration(timeoutSec)*time.Second,
		concurrency,
		"tcp",
		scanType,
	)
	
	// Determine port range
	if len(ports) > 0 {
		startPort := ports[0]
		endPort := ports[len(ports)-1]
		if len(ports) == 1 {
			endPort = startPort
		}
		
		fmt.Printf("Starting port scan on %s (ports: %s)\n", host, portRange)
		scanner.ScanPorts(startPort, endPort)
	}
	
	// Print results
	scanner.PrintResults(outputFormat)
}