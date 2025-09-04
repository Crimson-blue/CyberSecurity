#Async TCP Port Scanner

This is an asynchronous TCP port scanner written in Python.
It supports:

Scanning single IPs, multiple IPs, or entire CIDRs

Plain TCP or TLS connections (with auto-detection)

Banner grabbing (optionally with protocol probes)

Rate limiting & concurrency controls

JSON output (lines or array format)

Fallback to plain TCP if TLS fails

#📦 Requirements

Python 3.8+

Works on Linux, macOS, and Windows

No external dependencies are required (only Python standard library).

#⚡ Installation

Clone the repository or copy the script:

git clone https://github.com/yourusername/async-port-scanner.git
cd async-port-scanner
chmod +x scanner.py


Or just save the script as scanner.py.

#🚀 Usage

Run with Python:

python3 scanner.py --ips 192.168.1.10 --ports 22,80,443


Or make it executable:

./scanner.py --ips 192.168.1.10 --ports 22,80,443

🛠 Command-Line Arguments
Argument	Description	Example
--ips	One or more IPs	--ips 192.168.1.10 10.0.0.5
--cidr	CIDR ranges	--cidr 192.168.1.0/24 10.0.0.0/28
--ports	Ports or ranges	--ports 22,80,443,8000-8100
--mode	Scan mode: plain, tls, auto	--mode auto
--tls-ports	Ports treated as TLS in auto mode	--tls-ports 443,8443,993
--sni	TLS SNI hostname	--sni example.com
--connect-timeout	Connect timeout (s)	--connect-timeout 1.5
--read-timeout	Read timeout (s)	--read-timeout 1.0
--read-bytes	Max banner bytes	--read-bytes 1024
--concurrency	Max concurrent connections	--concurrency 500
--rate	Max attempts per second (0 = unlimited)	--rate 100
--burst	Burst size for token bucket limiter	--burst 200
--shuffle	Shuffle target order	--shuffle
--probe	Send protocol probes (HTTP HEAD, SMTP EHLO, etc.)	--probe
--fallback-plain	If TLS fails in auto mode, retry plain	--fallback-plain
--format	JSON format: lines or array	--format lines
--output	Output file (- = stdout)	--output results.json
--interactive	Prompt for IPs and ports if not provided	--interactive

📖 Examples
Scan a single host
python3 scanner.py --ips 192.168.1.10 --ports 22,80,443

Scan a CIDR range
python3 scanner.py --cidr 10.0.0.0/28 --ports 1-1024

Shuffle targets & limit rate
python3 scanner.py --cidr 192.168.1.0/24 --ports 80,443 --shuffle --rate 100 --burst 200

TLS auto mode with fallback
python3 scanner.py --ips example.com --ports 443,8443 --mode auto --fallback-plain

Save results to JSON file
python3 scanner.py --ips 192.168.1.10 --ports 22,80 --output scan_results.json --format array

#📊 Output

Example JSON (line format):

{"ip": "192.168.1.10", "port": 22, "state": "open", "is_tls": false, "banner": "SSH-2.0-OpenSSH_8.9p1", "connect_time_ms": 10.5}
{"ip": "192.168.1.10", "port": 80, "state": "open", "is_tls": false, "banner": "HTTP/1.1 200 OK", "connect_time_ms": 8.3}

#⚠️ Disclaimer

This tool is for educational and authorized security testing only.
Do not scan networks without proper permission.
