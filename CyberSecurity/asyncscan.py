#!/usr/bin/env python3
import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import os
import random
import ssl
import sys
import time
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any

# ---------------------------
# Rate limiter (token bucket)
# ---------------------------
class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: Optional[int] = None):
        # rate_per_sec <= 0 disables rate limiting
        self.rate = float(rate_per_sec)
        self.capacity = int(burst if burst is not None else max(1, int(self.rate) if self.rate > 0 else 1))
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        if self.rate > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    async def acquire(self, tokens: float = 1.0):
        if self.rate <= 0:
            return  # no rate limiting
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate if self.rate > 0 else 0.01
            await asyncio.sleep(wait)


# ---------------------------
# Helper parsing functions
# ---------------------------
def parse_ports(spec: str) -> List[int]:
    ports: Set[int] = set()
    for part in spec.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            start = int(a)
            end = int(b)
            if start > end:
                start, end = end, start
            for x in range(start, end + 1):
                if 1 <= x <= 65535:
                    ports.add(x)
        else:
            x = int(p)
            if 1 <= x <= 65535:
                ports.add(x)
    return sorted(ports)


def parse_hosts(specs: Iterable[str]) -> List[str]:
    # Accepts a mix of IPs and CIDRs (comma/space separated). Dedupes, preserves order.
    tokens: List[str] = []
    for spec in specs:
        if not spec:
            continue
        tokens.extend([t for t in spec.replace(",", " ").split() if t])

    result: List[str] = []
    for tok in tokens:
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.num_addresses == 1:  # /32 or /128
                    result.append(str(net.network_address))
                else:
                    for ip in net.hosts():
                        result.append(str(ip))
            else:
                ipaddress.ip_address(tok)  # validate
                result.append(tok)
        except ValueError:
            print(f"Warning: ignoring invalid IP/CIDR '{tok}'", file=sys.stderr)

    # Deduplicate while preserving order
    return list(dict.fromkeys(result))


# ---------------------------
# TLS utilities
# ---------------------------
def make_ssl_context(verify: bool = False) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def parse_peercert_dict(cert: Dict[str, Any]) -> Dict[str, Any]:
    if not cert:
        return {}

    def _flatten_name(n):
        d = {}
        for rdn in n:
            for key, val in rdn:
                d.setdefault(key, []).append(val)
        return {k: (v[0] if len(v) == 1 else v) for k, v in d.items()}

    subj = _flatten_name(cert.get("subject", ()))
    issr = _flatten_name(cert.get("issuer", ()))
    san = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]

    return {
        "subject": subj or None,
        "issuer": issr or None,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": san or None,
        "serial_number": cert.get("serialNumber"),
        "version": cert.get("version"),
    }


# ---------------------------
# Probing (optional nudges)
# ---------------------------
HTTP_PLAINTEXT_PORTS = {80, 8080, 8000, 8888}
HTTP_TLS_PORTS = {443, 8443, 9443}
SMTP_PORTS = {25, 587, 2525}
IMAP_PORTS = {143}
REDIS_PORTS = {6379}

def build_probe(port: int, host: str, is_tls: bool, enable: bool, sni: Optional[str]) -> Optional[bytes]:
    if not enable:
        return None
    try:
        if (not is_tls and port in HTTP_PLAINTEXT_PORTS) or (is_tls and port in HTTP_TLS_PORTS):
            host_hdr = sni or host
            req = f"HEAD / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: asyncscan/1.0\r\nConnection: close\r\n\r\n"
            return req.encode("ascii", errors="ignore")
        if port in SMTP_PORTS:
            return b"EHLO scanner.example\r\n"
        if port in IMAP_PORTS:
            return b"A1 CAPABILITY\r\n"
        if port in REDIS_PORTS:
            return b"PING\r\n"
        # default minimal nudge
        return b"\r\n"
    except Exception:
        return None


# ---------------------------
# Scanner logic
# ---------------------------
async def scan_one(
    ip: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
    read_bytes: int,
    is_tls: bool,
    ssl_ctx: Optional[ssl.SSLContext],
    sni: Optional[str],
    do_probe: bool,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "state": "unknown",
        "is_tls": bool(is_tls),
        "banner": None,
        "banner_base64": None,
        "connect_time_ms": None,
        "read_time_ms": None,
        "error": None,
        "tls": None,
    }

    loop = asyncio.get_running_loop()
    t0 = loop.time()

    try:
        if is_tls:
            conn_coro = asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=sni)
        else:
            conn_coro = asyncio.open_connection(ip, port)

        reader, writer = await asyncio.wait_for(conn_coro, timeout=connect_timeout)
        t1 = loop.time()
        result["state"] = "open"
        result["connect_time_ms"] = round((t1 - t0) * 1000.0, 2)

        # Optional probe first
        probe = build_probe(port, ip, is_tls, do_probe, sni)
        if probe:
            try:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=min(0.8, read_timeout))
            except Exception:
                pass

        banner_data = b""
        try:
            banner_data = await asyncio.wait_for(reader.read(read_bytes), timeout=read_timeout)
        except asyncio.TimeoutError:
            banner_data = b""
        except Exception as e:
            result["error"] = f"read-error: {e!r}"
        t2 = loop.time()
        result["read_time_ms"] = round((t2 - t1) * 1000.0, 2)

        if banner_data:
            try:
                result["banner"] = banner_data.decode("utf-8", errors="replace")
            except Exception:
                result["banner"] = None
            result["banner_base64"] = base64.b64encode(banner_data).decode("ascii")

        # TLS details if applicable
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            tls_info = {
                "version": ssl_obj.version(),
                "cipher": ssl_obj.cipher()[0] if ssl_obj.cipher() else None,
                "alpn": ssl_obj.selected_alpn_protocol(),
                "sni": sni,
                "peer_cert": None,
            }
            try:
                cert_dict = ssl_obj.getpeercert()
                tls_info["peer_cert"] = parse_peercert_dict(cert_dict) if cert_dict else None
            except Exception:
                tls_info["peer_cert"] = None
            result["tls"] = tls_info

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    except asyncio.TimeoutError:
        result["state"] = "timeout"
        result["error"] = "connect-timeout"
    except ConnectionRefusedError:
        result["state"] = "closed"
        result["error"] = "connection-refused"
    except ssl.SSLError as e:
        result["state"] = "error"
        result["error"] = f"ssl-error: {e.__class__.__name__}: {e}"
    except OSError as e:
        result["state"] = "error"
        result["error"] = f"os-error: {e.__class__.__name__}: {e}"
    except Exception as e:
        result["state"] = "error"
        result["error"] = f"unexpected: {e.__class__.__name__}: {e}"

    return result


# ---------------------------
# Worker and writer
# ---------------------------
async def worker(
    name: str,
    job_q: "asyncio.Queue[Tuple[str, int]]",
    out_q: "asyncio.Queue[Dict[str, Any]]",
    sem: asyncio.Semaphore,
    rate: RateLimiter,
    args,
    tls_ports: Set[int],
    ssl_ctx: ssl.SSLContext,
):
    while True:
        ip, port = await job_q.get()
        try:
            await rate.acquire()
            async with sem:
                mode = args.mode  # plain | tls | auto
                is_tls = False
                if mode == "tls":
                    is_tls = True
                elif mode == "auto":
                    is_tls = port in tls_ports
                else:
                    is_tls = False

                result = await scan_one(
                    ip=ip,
                    port=port,
                    connect_timeout=args.connect_timeout,
                    read_timeout=args.read_timeout,
                    read_bytes=args.read_bytes,
                    is_tls=is_tls,
                    ssl_ctx=ssl_ctx if is_tls else None,
                    sni=args.sni,
                    do_probe=args.probe,
                )

                # Optional fallback: if TLS failed at connect and auto mode, try plain
                if args.fallback_plain and mode == "auto" and is_tls and result["state"] in ("timeout", "error", "closed"):
                    plain_result = await scan_one(
                        ip=ip,
                        port=port,
                        connect_timeout=args.connect_timeout,
                        read_timeout=args.read_timeout,
                        read_bytes=args.read_bytes,
                        is_tls=False,
                        ssl_ctx=None,
                        sni=None,
                        do_probe=args.probe,
                    )
                    plain_result["tls_error"] = result.get("error")
                    result = plain_result

                await out_q.put(result)
        finally:
            job_q.task_done()


async def writer_task(
    out_q: "asyncio.Queue[Dict[str, Any]]",
    total_items: int,
    fmt: str,
    out_fp,
):
    count = 0
    if fmt == "array":
        out_fp.write("[")
        first = True

    while count < total_items:
        item = await out_q.get()
        try:
            if fmt == "lines":
                out_fp.write(json.dumps(item, ensure_ascii=False) + "\n")
            else:
                if first:
                    first = False
                else:
                    out_fp.write(",")
                out_fp.write(json.dumps(item, ensure_ascii=False))
            count += 1
        finally:
            out_q.task_done()

    if fmt == "array":
        out_fp.write("]\n")
    try:
        out_fp.flush()
    except Exception:
        pass


# ---------------------------
# Main and CLI
# ---------------------------
def default_tls_ports() -> Set[int]:
    return {
        443, 8443, 9443,   # HTTPS
        465, 587,          # SMTPS/Submission (implicit TLS on 465)
        993, 995,          # IMAPS, POP3S
        990,               # FTPS
        992,               # TelnetS
        994,               # IRCS
    }

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Async TCP port scanner with banner grabbing, TLS support, CIDR/IP input, rate limiting, and JSON output.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # You can provide --cidr and/or --ips, or use --interactive to be prompted.
    p.add_argument("--cidr", nargs="+", help="CIDR(s) to scan (e.g., 192.168.1.0/24 10.0.0.0/28).")
    p.add_argument("--ips", nargs="+", help="IP address(es) (e.g., 192.168.1.10 10.0.0.5). You can mix with --cidr.")
    p.add_argument("--interactive", action="store_true", help="Prompt for IPs/CIDRs and ports if not provided.")
    p.add_argument("--ports", help="Ports to scan, e.g. '22,80,443,8000-8100'.")
    p.add_argument("--mode", choices=["plain", "tls", "auto"], default="auto", help="Scan mode for TLS.")
    p.add_argument("--tls-ports", default=",".join(str(x) for x in sorted(default_tls_ports())),
                   help="Ports to treat as TLS in auto mode (comma-separated).")
    p.add_argument("--sni", default=None, help="SNI to use for TLS handshakes (host name).")
    p.add_argument("--connect-timeout", type=float, default=1.5, help="Connect timeout in seconds.")
    p.add_argument("--read-timeout", type=float, default=1.0, help="Read timeout in seconds.")
    p.add_argument("--read-bytes", type=int, default=1024, help="Max banner bytes to read.")
    p.add_argument("--concurrency", type=int, default=500, help="Max concurrent connections.")
    p.add_argument("--rate", type=float, default=0.0, help="Max connection attempts per second (0=unlimited).")
    p.add_argument("--burst", type=int, default=None, help="Token bucket burst size (defaults to ~rate).")
    p.add_argument("--shuffle", action="store_true", help="Shuffle target order.")
    p.add_argument("--probe", action="store_true", help="Send light protocol probes (e.g., HTTP HEAD) before reading banner.")
    p.add_argument("--fallback-plain", action="store_true", help="On TLS auto mode failure, try plain connect.")
    p.add_argument("--format", choices=["lines", "array"], default="lines", help="JSON output format.")
    p.add_argument("--output", default="-", help="Output file ('-' for stdout).")
    return p


async def main_async(args):
    # Prompt if interactive or values missing
    if args.interactive or (not args.cidr and not args.ips):
        try:
            host_input = input("Enter IPs or CIDRs (comma/space separated): ").strip()
        except EOFError:
            host_input = ""
        if host_input:
            args.ips = (args.ips or []) + [host_input]

    if not args.ports:
        try:
            args.ports = input("Enter ports (e.g., 22,80,443 or 1-1024): ").strip()
        except EOFError:
            args.ports = ""

    ips = parse_hosts((args.ips or []) + (args.cidr or []))
    if args.shuffle:
        random.shuffle(ips)

    if not args.ports:
        print("No ports provided. Use --ports or enter them when prompted.", file=sys.stderr)
        return 1

    ports = parse_ports(args.ports)
    tls_ports = set(parse_ports(args.tls_ports)) if args.mode == "auto" else set()

    targets: List[Tuple[str, int]] = [(ip, port) for ip in ips for port in ports]
    total = len(targets)

    if total == 0:
        print("No targets to scan (check IPs/CIDRs and ports).", file=sys.stderr)
        return 1

    # Output
    if args.output == "-" or args.output.lower() == "stdout":
        out_fp = sys.stdout
    else:
        out_fp = open(args.output, "w", encoding="utf-8")

    # Queues and controls
    job_q: asyncio.Queue = asyncio.Queue(maxsize=min(10000, total))
    out_q: asyncio.Queue = asyncio.Queue(maxsize=min(10000, total))
    sem = asyncio.Semaphore(args.concurrency)
    rate = RateLimiter(args.rate, burst=args.burst)
    ssl_ctx = make_ssl_context(verify=False)

    # Enqueue jobs
    for t in targets:
        await job_q.put(t)

    # Writer
    writer = asyncio.create_task(writer_task(out_q, total_items=total, fmt=args.format, out_fp=out_fp))

    # Workers
    workers = [
        asyncio.create_task(worker(f"w{i+1}", job_q, out_q, sem, rate, args, tls_ports, ssl_ctx))
        for i in range(min(args.concurrency, os.cpu_count() * 100 if os.cpu_count() else 1000))
    ]

    # Progress the work
    try:
        await job_q.join()      # all jobs processed
        await out_q.join()      # all results written
    except KeyboardInterrupt:
        print("\nCancelled by user, shutting down...", file=sys.stderr)
    finally:
        for w in workers:
            w.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*workers, return_exceptions=True)
        try:
            writer.cancel()
            with contextlib.suppress(Exception):
                await writer
        except Exception:
            pass
        if out_fp is not sys.stdout:
            out_fp.close()

    return 0


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    random.seed()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())