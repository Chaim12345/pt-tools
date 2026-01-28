# Go Port Scanner with Nmap-like Capabilities

A lightweight, fast port scanner written in Go with nmap-like features for penetration testing and network reconnaissance.

## Features

- **TCP Connect Scanning**: Standard TCP connection scanning
- **UDP Scanning**: Basic UDP port scanning
- **Service Detection**: Identifies common services based on port numbers
- **Banner Grabbing**: Attempts to grab service banners from open ports
- **Concurrent Scanning**: Multi-threaded scanning for speed
- **Multiple Output Formats**: Nmap-like, simple, verbose, and JSON output
- **Flexible Port Specification**: Scan ranges, individual ports, or comma-separated lists

## Installation

### Prerequisites
- Go 1.19 or higher

### Building from Source
```bash
go build -o portscanner portscanner.go
```

### Running without Building
```bash
go run portscanner.go -host example.com -ports 1-1000
```

## Usage

### Basic Syntax
```bash
./portscanner -host <target> [-ports <port-range>] [-timeout <seconds>] [-concurrency <threads>] [-scan-type <type>] [-output <format>]
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-host` | Target host to scan (required) | - |
| `-ports` | Ports to scan (e.g., `1-1000`, `80,443,8080`) | `1-1000` |
| `-timeout` | Timeout in seconds for each connection | `2` |
| `-concurrency` | Number of concurrent scans | `100` |
| `-scan-type` | Scan type (`tcp`, `udp`) | `tcp` |
| `-output` | Output format (`nmap`, `simple`, `verbose`, `json`) | `nmap` |

### Examples

1. **Basic TCP scan of common ports**:
   ```bash
   ./portscanner -host example.com -ports 1-1000
   ```

2. **Scan specific ports**:
   ```bash
   ./portscanner -host example.com -ports 22,80,443,8080,8443
   ```

3. **UDP scan**:
   ```bash
   ./portscanner -host example.com -ports 53,67,68,123,161 -scan-type udp
   ```

4. **Verbose output with JSON format**:
   ```bash
   ./portscanner -host example.com -ports 80,443 -output json
   ```

5. **Faster scan with higher concurrency**:
   ```bash
   ./portscanner -host example.com -ports 1-65535 -concurrency 500 -timeout 1
   ```

## Output Formats

### Nmap-like Format (Default)
```
Starting Nmap-like port scanner at 2024-01-28 15:04
Scanning example.com
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql

Nmap-like scan completed: 3 open ports
```

### Simple Format
```
Port 80/tcp open (http)
Port 443/tcp open (https)
Port 3306/tcp open (mysql)
```

### Verbose Format
```
Scan report for example.com
PORT     STATE SERVICE
80/tcp   open  http
  Banner: HTTP/1.1 200 OK
443/tcp  open  https
3306/tcp open  mysql

Scanned 3 ports
```

### JSON Format
```json
[
  {
    "port": 80,
    "state": "open",
    "service": "http",
    "banner": "HTTP/1.1 200 OK",
    "protocol": "tcp"
  },
  {
    "port": 443,
    "state": "open",
    "service": "https",
    "protocol": "tcp"
  }
]
```

## Service Detection

The scanner includes a comprehensive database of common port-to-service mappings including:

- **Web Services**: HTTP (80), HTTPS (443), HTTP-Alt (8080, 8443, 8888)
- **Database Services**: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- **Remote Access**: SSH (22), RDP (3389), VNC (5900), Telnet (23)
- **Network Services**: DNS (53), DHCP (67,68), NTP (123), SNMP (161)
- **Email Services**: SMTP (25), POP3 (110), IMAP (143), SMTP-SSL (465)
- **File Services**: FTP (21), SMB (445), NFS (2049)

## Limitations

1. **SYN Scanning**: Currently only supports TCP connect scanning (requires root privileges for raw socket access)
2. **UDP Accuracy**: UDP scanning may show false positives due to connectionless nature
3. **Service Detection**: Based on port numbers only, not actual service fingerprinting
4. **Firewall Evasion**: No advanced firewall evasion techniques

## Security Considerations

- Use responsibly and only on networks you own or have permission to test
- Port scanning may be detected by intrusion detection systems
- Some networks may block or throttle port scanning activities
- Always obtain proper authorization before scanning

## Future Enhancements

Planned features for future versions:
- SYN scan (raw socket implementation)
- OS fingerprinting
- Version detection
- Scriptable scanning engine
- XML output format compatible with nmap
- Timing templates (T0-T5 like nmap)
- Exclude ports/hosts functionality

## License

This tool is provided for educational and authorized penetration testing purposes only.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.