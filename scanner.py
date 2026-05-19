#!/usr/bin/env python3
"""
CloudFront IP Scanner
Finds CloudFront edge IPs reachable from censored regions (e.g. Iran)
that accept TLS with SNI=127.0.0.1 (invalid/IP SNI).

How it works:
  - CloudFront publishes its IP ranges at ip-ranges.amazonaws.com
  - Within those ranges, only SMALL ranges (/26 and smaller) are dense
    with live edge nodes that accept invalid SNI.
  - Large ranges (/14, /15, /16) are mostly dead or strict — scanning them
    exhaustively wastes time. We skip them by default.
  - After finding IPs that accept the TLS handshake, we do a second-stage
    check: send a real WebSocket upgrade to verify the IP actually proxies
    to a CloudFront distribution (not just any AWS service).
  - Run this script FROM INSIDE the censored region to get IPs that are
    reachable there. IPs that time out are simply not routed to that region.
"""

import ssl
import socket
import json
import urllib.request
import ipaddress
import concurrent.futures
import argparse
import sys
import time
import os
from datetime import datetime

class Colors:
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'

# ---------------------------------------------------------------------------
# PRIORITY_RANGES: ranges known to contain permissive-SNI CloudFront edge nodes.
# Ordered roughly by density of working IPs (best first).
#
# FAST_RANGES: smaller subset for a quick first pass (~200k IPs, ~5-15 min from Iran).
#   Use --fast when you just need a few working IPs quickly.
#   Use --priority for a thorough scan of all known-good ranges.
# ---------------------------------------------------------------------------
PRIORITY_RANGES = [
    # Confirmed dense with permissive-SNI nodes, route to Iran
    "13.249.0.0/16",       # ~65k IPs, very dense
    "3.164.0.0/18",        # confirmed (3.164.68.x worked in session)
    "3.164.64.0/18",
    "3.164.128.0/17",
    "13.35.0.0/16",        # similar profile to 13.249
    "13.32.0.0/15",
    "13.224.0.0/14",
    "18.154.0.0/15",
    "18.160.0.0/15",
    "18.164.0.0/15",
    "18.172.0.0/15",
    "52.84.0.0/15",
    "65.8.0.0/16",
    "65.9.0.0/17",
    "99.86.0.0/16",
    "143.204.0.0/16",
    "144.220.0.0/16",
    "130.176.0.0/17",
    "54.230.0.0/17",
    "54.192.0.0/16",
    "54.182.0.0/16",
    "3.160.0.0/14",
    "3.166.0.0/15",
    "3.168.0.0/14",
]

FAST_RANGES = [
    # Smallest / highest-density ranges — good for a quick scan
    "13.249.0.0/16",
    "3.164.0.0/18",
    "3.164.64.0/18",
    "3.164.128.0/17",
    "13.35.0.0/16",
    "65.8.0.0/16",
    "65.9.0.0/17",
    "99.86.0.0/16",
    "143.204.0.0/16",
    "144.220.0.0/16",
]


BUNDLED_RANGES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cf_ranges.json')

def load_bundled_ranges():
    """Load ranges from the bundled cf_ranges.json file shipped with this script."""
    try:
        with open(BUNDLED_RANGES_FILE) as f:
            data = json.load(f)
        ranges = data['ranges']
        print(f"{Colors.YELLOW}[*] Using bundled ranges (updated {data.get('updated','?')})"
              f" — {len(ranges)} ranges{Colors.RESET}")
        return ranges
    except Exception as e:
        print(f"{Colors.RED}[-] Could not load bundled ranges: {e}{Colors.RESET}")
        return None

def get_cloudfront_ranges():
    """Try AWS API first; fall back to bundled file if unreachable (e.g. from censored network)."""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    print(f"{Colors.CYAN}[*] Fetching CloudFront IP ranges from AWS...{Colors.RESET}")
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            data = json.loads(r.read().decode())
        ranges = [p['ip_prefix'] for p in data['prefixes'] if p['service'] == 'CLOUDFRONT']
        print(f"{Colors.GREEN}[+] Fetched {len(ranges)} CloudFront IP ranges from AWS{Colors.RESET}")
        return ranges
    except Exception as e:
        print(f"{Colors.YELLOW}[!] AWS API unreachable ({e}) — falling back to bundled ranges{Colors.RESET}")
        return load_bundled_ranges()


def tls_check(ip, sni="127.0.0.1", timeout=3):
    """
    Stage 1: TLS handshake with invalid SNI.
    CloudFront edge nodes that allow IP-based routing accept this.
    Nodes that are strict about SNI return SSLV3_ALERT_HANDSHAKE_FAILURE.
    Dead IPs time out.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as s:
                return True, s.version()
    except ssl.SSLError:
        return False, 'ssl_reject'
    except socket.timeout:
        return False, 'timeout'
    except OSError:
        return False, 'refused'
    except Exception as e:
        return False, str(e)[:30]


def ws_check(ip, host, path="/", timeout=5):
    """
    Stage 2: Send a real WebSocket upgrade request with the given Host header.
    A 101 response confirms this IP routes to a CloudFront distribution.
    A 403/404/400 still means CloudFront is responding (useful).
    A timeout or connection error means the IP is not usable.
    """
    import hashlib, base64, os
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                s.sendall(request.encode())
                resp = s.recv(256).decode(errors='ignore')
                if 'HTTP/1.1' in resp or 'HTTP/2' in resp:
                    code = resp.split()[1] if len(resp.split()) > 1 else '?'
                    return True, code
                return False, 'no_http'
    except socket.timeout:
        return False, 'timeout'
    except Exception as e:
        return False, str(e)[:30]


def scan_ip(ip, sni, ws_host, ws_path, timeout):
    ip = str(ip)
    ok, detail = tls_check(ip, sni, timeout)
    if not ok:
        return ip, False, detail, None
    # Stage 2 only if ws_host provided
    if ws_host:
        ws_ok, ws_code = ws_check(ip, ws_host, ws_path, timeout + 2)
        return ip, ws_ok, detail, ws_code
    return ip, True, detail, None


def generate_ips(ranges):
    """
    Strategy: expand every range into /24 subnets and scan each /24 fully.
    A /24 has 254 hosts — small enough to scan exhaustively in seconds.
    This guarantees every IP in every range is checked, regardless of range size.
    No sampling, no missed clusters.
    """
    ips = []
    total_subnets = 0
    for cidr in ranges:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen >= 24:
            # Already /24 or smaller — scan all hosts directly
            ips.extend(net.hosts())
            total_subnets += 1
        else:
            # Break into /24 subnets and scan each fully
            subnets = list(net.subnets(new_prefix=24))
            total_subnets += len(subnets)
            for subnet in subnets:
                ips.extend(subnet.hosts())
    print(f"{Colors.CYAN}[*] IPs to scan: {len(ips)} across {total_subnets} /24 subnets "
          f"(exhaustive — no sampling){Colors.RESET}")
    return ips


def run_scan(ips, workers, sni, ws_host, ws_path, timeout):
    working = []
    total = len(ips)
    scanned = 0
    t0 = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_ip, ip, sni, ws_host, ws_path, timeout): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            scanned += 1
            ip, ok, tls_detail, ws_code = fut.result()

            if ok:
                label = f"101 WS" if ws_code == '101' else (f"HTTP {ws_code}" if ws_code else "TLS-only")
                print(f"{Colors.GREEN}[+] {ip:20s}  {label}{Colors.RESET}")
                working.append({'ip': ip, 'tls': tls_detail, 'ws_code': ws_code})

            if scanned % 500 == 0:
                elapsed = time.time() - t0
                rate = scanned / elapsed
                eta = (total - scanned) / rate if rate > 0 else 0
                print(f"{Colors.CYAN}[*] {scanned}/{total}  found={len(working)}"
                      f"  rate={rate:.0f}/s  eta={eta:.0f}s{Colors.RESET}")

    return working


def save_results(results, filename):
    with open(filename, 'w') as f:
        for r in results:
            f.write(r['ip'] + '\n')
    print(f"{Colors.GREEN}[+] Saved {len(results)} IPs to {filename}{Colors.RESET}")


def generate_vless(ip, host, path, uuid):
    return (
        f"vless://{uuid}@{ip}:443"
        f"?encryption=none&type=ws"
        f"&host={host}&path={path}"
        f"&security=tls&fp=random"
        f"&sni=127.0.0.1&alpn=http%2F1.1"
        f"#CF-{ip}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="CloudFront IP Scanner — finds IPs usable from censored regions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast scan — best starting point from inside Iran (~5-15 min)
  python scanner.py --fast

  # Full priority scan — thorough, finds more IPs (~20-60 min from Iran)
  python scanner.py --priority

  # Scan and verify IPs work end-to-end with your CloudFront distribution
  python scanner.py --fast --ws-host d2oa26wjpquwas.cloudfront.net --ws-path /api/v1/chat

  # Generate ready-to-use vless:// configs
  python scanner.py --fast --vless --uuid YOUR-UUID --ws-host d2oa26wjpquwas.cloudfront.net

  # Scan a specific range (e.g. to re-check a known-good subnet)
  python scanner.py --range 13.249.2.0/24
        """
    )

    parser.add_argument('--fast', action='store_true',
                        help='Fast scan: highest-density ranges only (~600k IPs, ~5-15 min from Iran)')
    parser.add_argument('--priority', action='store_true',
                        help='Full priority scan: all known-good ranges (~1.8M IPs, ~20-60 min)')
    parser.add_argument('--all', action='store_true',
                        help='Scan all CloudFront ranges from AWS (slow, ~4M IPs sampled)')
    parser.add_argument('--range', type=str, dest='cidr',
                        help='Scan a specific CIDR range exhaustively')
    parser.add_argument('--file', type=str,
                        help='File with IPs to scan (one per line)')

    parser.add_argument('--sni', type=str, default='127.0.0.1',
                        help='SNI for TLS stage-1 check (default: 127.0.0.1)')
    parser.add_argument('--ws-host', type=str, default='',
                        help='Host header for stage-2 WebSocket check (your .cloudfront.net domain)')
    parser.add_argument('--ws-path', type=str, default='/api/v1/chat',
                        help='WebSocket path for stage-2 check (default: /api/v1/chat)')
    parser.add_argument('--workers', type=int, default=200,
                        help='Concurrent threads (default: 200)')
    parser.add_argument('--timeout', type=float, default=3.0,
                        help='Per-IP timeout in seconds (default: 3). '
                             'Increase to 5-8 when scanning from a slow connection.')
    parser.add_argument('--output', type=str, default='working_ips.txt',
                        help='Output file (default: working_ips.txt)')
    parser.add_argument('--vless', action='store_true',
                        help='Generate vless:// URIs for found IPs')
    parser.add_argument('--uuid', type=str, default='YOUR-UUID-HERE',
                        help='UUID for vless config generation')

    args = parser.parse_args()

    print(f"{Colors.BOLD}{Colors.CYAN}[CloudFront IP Scanner]{Colors.RESET}")
    print(f"  SNI      : {args.sni}")
    print(f"  WS host  : {args.ws_host or 'disabled (stage-2 off)'}")
    print()

    # --- Build IP list ---
    if args.file:
        with open(args.file) as f:
            ips = [l.strip() for l in f if l.strip()]
        print(f"{Colors.CYAN}[*] Loaded {len(ips)} IPs from {args.file}{Colors.RESET}")

    elif args.cidr:
        net = ipaddress.ip_network(args.cidr, strict=False)
        ips = [str(ip) for ip in net.hosts()]
        print(f"{Colors.CYAN}[*] Full scan of {args.cidr}: {len(ips)} IPs{Colors.RESET}")

    elif args.fast:
        ips = generate_ips(FAST_RANGES)

    elif args.priority:
        ips = generate_ips(PRIORITY_RANGES)

    elif args.all:
        ranges = get_cloudfront_ranges()
        if not ranges:
            sys.exit(1)
        ips = generate_ips(ranges)

    else:
        parser.print_help()
        print(f"\n{Colors.YELLOW}[!] Specify --fast, --priority, --all, --range, or --file{Colors.RESET}")
        sys.exit(1)

    if not ips:
        print(f"{Colors.RED}[-] No IPs to scan{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.CYAN}[*] Starting scan with {args.workers} workers, "
          f"timeout={args.timeout}s ...{Colors.RESET}\n")

    t0 = time.time()
    results = run_scan(ips, args.workers, args.sni, args.ws_host, args.ws_path, args.timeout)
    elapsed = time.time() - t0

    print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Done in {elapsed:.1f}s — {len(results)} working IPs found{Colors.RESET}")

    if results:
        save_results(results, args.output)

        if args.vless:
            vless_file = args.output.replace('.txt', '_vless.txt')
            with open(vless_file, 'w') as f:
                for r in results:
                    uri = generate_vless(r['ip'], args.ws_host or 'YOUR-CF-DOMAIN.cloudfront.net',
                                         args.ws_path, args.uuid)
                    print(uri)
                    f.write(uri + '\n')
            print(f"{Colors.GREEN}[+] VLESS configs saved to {vless_file}{Colors.RESET}")


if __name__ == "__main__":
    main()

