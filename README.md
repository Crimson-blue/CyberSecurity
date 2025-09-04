# ⚡ Async TCP Port Scanner

Async TCP Port Scanner is a high-performance, asynchronous scanner built in Python.  
It supports **plain TCP & TLS**, **CIDR/IP scanning**, **banner grabbing**, **rate limiting**, and **JSON output** — all powered by Python’s `asyncio`.

---

## 📦 Features

- 🚀 Asynchronous TCP scanner with high concurrency  
- 🔐 TLS support (manual, auto-detect, and fallback)  
- 🪪 Banner grabbing (HTTP, SMTP, IMAP, Redis probes)  
- 📊 JSON output (`lines` or `array` format)  
- 🎯 CIDR & IP range scanning  
- ⚡ Rate limiting (token bucket algorithm)  
- 🔄 Fallback to plain TCP on TLS failure  

---

## 🛠️ Prerequisites

Install Python **3.8+**:

```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

No external dependencies are required (standard library only).

---

## 🐍 Running Locally

Clone the repo:

```bash
git clone https://github.com/YourUsername/async-port-scanner.git
cd async-port-scanner
chmod +x scanner.py
```

Run a simple scan:

```bash
python3 scanner.py --ips 127.0.0.1 --ports 22,80,443
```

---

## 📖 Examples

### 🔍 Scan a single host
```bash
python3 scanner.py --ips 192.168.1.10 --ports 22,80,443
```

### 🌐 Scan a CIDR range
```bash
python3 scanner.py --cidr 10.0.0.0/28 --ports 1-1024
```

### 🎲 Shuffle targets & rate-limit
```bash
python3 scanner.py --cidr 192.168.1.0/24 --ports 80,443 --shuffle --rate 100 --burst 200
```

### 🔐 TLS auto mode with fallback
```bash
python3 scanner.py --ips example.com --ports 443,8443 --mode auto --fallback-plain
```

### 💾 Save results to JSON
```bash
python3 scanner.py --ips 192.168.1.10 --ports 22,80 --output scan_results.json --format array
```

---

## 📊 Output

Example JSON (line format):

```json
{"ip": "192.168.1.10", "port": 22, "state": "open", "is_tls": false, "banner": "SSH-2.0-OpenSSH_8.9p1", "connect_time_ms": 10.5}
{"ip": "192.168.1.10", "port": 80, "state": "open", "is_tls": false, "banner": "HTTP/1.1 200 OK", "connect_time_ms": 8.3}
```

---

## ⚡ Quick Start

For a quick test on your own machine:

```bash
python3 scanner.py --ips 127.0.0.1 --ports 22,80,443 --probe
```

---
