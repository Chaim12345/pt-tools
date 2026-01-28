#!/bin/bash

# Port Scanner Examples Script
# This script demonstrates various usage examples of the Go port scanner

echo "=============================================="
echo "Go Port Scanner Examples"
echo "=============================================="

# First, let's check if the port scanner is built
if [ ! -f "./portscanner" ]; then
    echo "Building port scanner..."
    go build -o portscanner portscanner.go
    if [ $? -ne 0 ]; then
        echo "Failed to build port scanner. Please ensure Go is installed."
        exit 1
    fi
fi

echo ""
echo "Example 1: Basic TCP scan of common ports"
echo "------------------------------------------"
echo "Command: ./portscanner -host scanme.nmap.org -ports 1-100"
echo ""
./portscanner -host scanme.nmap.org -ports 1-100

echo ""
echo "Example 2: Scan specific web ports"
echo "-----------------------------------"
echo "Command: ./portscanner -host example.com -ports 80,443,8080,8443"
echo ""
echo "Note: Replace 'example.com' with actual target"
echo ""

echo "Example 3: UDP scan of common UDP ports"
echo "----------------------------------------"
echo "Command: ./portscanner -host target.com -ports 53,67,68,123,161 -scan-type udp"
echo ""
echo "Note: Replace 'target.com' with actual target"
echo ""

echo "Example 4: JSON output format"
echo "-----------------------------"
echo "Command: ./portscanner -host scanme.nmap.org -ports 22,80,443 -output json"
echo ""
./portscanner -host scanme.nmap.org -ports 22,80,443 -output json

echo ""
echo "Example 5: Verbose output with banner grabbing"
echo "----------------------------------------------"
echo "Command: ./portscanner -host scanme.nmap.org -ports 22,80,443 -output verbose"
echo ""
./portscanner -host scanme.nmap.org -ports 22,80,443 -output verbose

echo ""
echo "Example 6: High-concurrency fast scan"
echo "-------------------------------------"
echo "Command: ./portscanner -host target.com -ports 1-1000 -concurrency 200 -timeout 1"
echo ""
echo "Note: Replace 'target.com' with actual target"
echo ""

echo "Example 7: Simple output format"
echo "-------------------------------"
echo "Command: ./portscanner -host scanme.nmap.org -ports 22,80,443 -output simple"
echo ""
./portscanner -host scanme.nmap.org -ports 22,80,443 -output simple

echo ""
echo "=============================================="
echo "Advanced Usage Examples"
echo "=============================================="

echo ""
echo "Example 8: Scanning multiple port ranges"
echo "----------------------------------------"
echo "Command: ./portscanner -host target.com -ports 1-1024,3000-4000,8000-9000"
echo ""

echo "Example 9: Scanning with custom timeout"
echo "---------------------------------------"
echo "Command: ./portscanner -host slow-server.com -ports 1-100 -timeout 5"
echo ""

echo "Example 10: Saving output to file"
echo "---------------------------------"
echo "Command: ./portscanner -host target.com -ports 1-1000 -output json > scan_results.json"
echo "Command: ./portscanner -host target.com -ports 1-1000 > nmap_style_output.txt"
echo ""

echo "=============================================="
echo "Tips for Effective Scanning"
echo "=============================================="
echo "1. Start with common ports (1-1000) before full range scans"
echo "2. Use higher concurrency (200-500) for faster scans on reliable networks"
echo "3. Use lower timeout (1-2 seconds) for internal networks, higher (3-5) for external"
echo "4. UDP scans are slower and less reliable than TCP scans"
echo "5. Always scan responsibly and with proper authorization"
echo "6. Consider network bandwidth and target system load"
echo "7. Use JSON output for programmatic processing of results"
echo "8. Combine with other tools for comprehensive network assessment"

echo ""
echo "=============================================="
echo "Legal and Ethical Considerations"
echo "=============================================="
echo "IMPORTANT: Only scan systems you own or have explicit permission to test."
echo "Unauthorized port scanning may be illegal and violate terms of service."
echo "Always obtain written authorization before scanning any network."
echo ""

echo "Script completed. Review the examples above for usage patterns."