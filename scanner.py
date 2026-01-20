#!/usr/bin/env python3
"""
CloudFront IP Scanner
Finds CloudFront edge IPs that accept connections with SNI=127.0.0.1
For CTF/educational purposes
"""

import ssl
import socket
import json
import urllib.request
import ipaddress
import concurrent.futures
import argparse
import sys
from datetime import datetime

# Colors for terminal
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def get_cloudfront_ranges():
    """Fetch official CloudFront IP ranges from AWS"""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    print(f"{Colors.CYAN}[*] Fetching CloudFront IP ranges from AWS...{Colors.RESET}")
    
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())
        
        ranges = [
            prefix['ip_prefix'] 
            for prefix in data['prefixes'] 
            if prefix['service'] == 'CLOUDFRONT'
        ]
        print(f"{Colors.GREEN}[+] Found {len(ranges)} CloudFront IP ranges{Colors.RESET}")
        return ranges
    except Exception as e:
        print(f"{Colors.RED}[-] Failed to fetch ranges: {e}{Colors.RESET}")
        return None

# Fallback ranges if AWS API is unavailable
FALLBACK_RANGES = [
    "3.160.0.0/14",
    "13.32.0.0/15",
    "13.224.0.0/14",
    "18.64.0.0/14",
    "52.84.0.0/14",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "99.84.0.0/16",
    "108.138.0.0/15",
    "108.156.0.0/14",
    "116.129.226.0/25",
    "130.176.0.0/17",
    "143.204.0.0/16",
    "144.220.0.0/16",
    "205.251.192.0/19",
]

def check_ip(ip, sni="127.0.0.1", timeout=3):
    """Check if IP accepts TLS connection with given SNI"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((str(ip), 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                # Try to get certificate info
                cert = ssock.getpeercert(binary_form=True)
                return {
                    'ip': str(ip),
                    'status': 'working',
                    'tls_version': ssock.version(),
                }
    except socket.timeout:
        return {'ip': str(ip), 'status': 'timeout'}
    except ConnectionRefusedError:
        return {'ip': str(ip), 'status': 'refused'}
    except ssl.SSLError as e:
        return {'ip': str(ip), 'status': f'ssl_error: {e.reason}'}
    except Exception as e:
        return {'ip': str(ip), 'status': f'error: {type(e).__name__}'}

def generate_ips_from_ranges(ranges, sample_per_range=50):
    """Generate IPs to scan from CIDR ranges"""
    ips = []
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())
            
            if len(hosts) <= sample_per_range:
                ips.extend(hosts)
            else:
                # Sample evenly across the range
                step = len(hosts) // sample_per_range
                ips.extend(hosts[::step][:sample_per_range])
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error parsing {cidr}: {e}{Colors.RESET}")
    
    return ips

def scan_range_full(cidr, workers=100, sni="127.0.0.1"):
    """Scan entire CIDR range"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ips = list(network.hosts())
    except Exception as e:
        print(f"{Colors.RED}[-] Invalid CIDR: {e}{Colors.RESET}")
        return []
    
    print(f"{Colors.CYAN}[*] Scanning {len(ips)} IPs in {cidr}...{Colors.RESET}")
    return scan_ips(ips, workers, sni)

def scan_ips(ips, workers=100, sni="127.0.0.1"):
    """Scan list of IPs with thread pool"""
    working = []
    total = len(ips)
    scanned = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_ip, ip, sni): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(futures):
            scanned += 1
            result = future.result()
            
            if result['status'] == 'working':
                working.append(result)
                print(f"{Colors.GREEN}[+] FOUND: {result['ip']} ({result['tls_version']}){Colors.RESET}")
            
            # Progress update every 100 IPs
            if scanned % 100 == 0:
                print(f"{Colors.CYAN}[*] Progress: {scanned}/{total} ({len(working)} found){Colors.RESET}")
    
    return working

def save_results(results, filename):
    """Save results to file"""
    with open(filename, 'w') as f:
        for r in results:
            f.write(r['ip'] + '\n')
    print(f"{Colors.GREEN}[+] Saved {len(results)} IPs to {filename}{Colors.RESET}")

def generate_vless_config(ip, host="d3ub1fvy78o8cz.cloudfront.net", path="/nocky"):
    """Generate VLESS URL template"""
    uuid = "506800dd-3e26-40ed-92cc-cc88710e4a46"  # Example UUID
    return f"vless://{uuid}@{ip}:443?encryption=none&type=ws&host={host}&path={path}&security=tls&fp=chrome&sni=127.0.0.1&alpn=http/1.1&allowInsecure=true#CF-{ip}"

def main():
    parser = argparse.ArgumentParser(
        description="CloudFront IP Scanner - Find IPs accepting SNI=127.0.0.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan (samples from all ranges)
  python3 cloudfront_scanner.py --quick
  
  # Scan specific range fully
  python3 cloudfront_scanner.py --range 3.160.144.0/22
  
  # Scan with custom SNI
  python3 cloudfront_scanner.py --quick --sni localhost
  
  # Scan specific IPs from file
  python3 cloudfront_scanner.py --file ips.txt
  
  # Generate VLESS configs for found IPs
  python3 cloudfront_scanner.py --quick --vless
        """
    )
    
    parser.add_argument('--quick', action='store_true', 
                        help='Quick scan: sample IPs from all CloudFront ranges')
    parser.add_argument('--range', type=str, 
                        help='Scan specific CIDR range (e.g., 3.160.144.0/22)')
    parser.add_argument('--file', type=str,
                        help='File with IPs to scan (one per line)')
    parser.add_argument('--sni', type=str, default='127.0.0.1',
                        help='SNI to use for TLS connection (default: 127.0.0.1)')
    parser.add_argument('--workers', type=int, default=100,
                        help='Number of concurrent workers (default: 100)')
    parser.add_argument('--samples', type=int, default=30,
                        help='IPs to sample per range in quick mode (default: 30)')
    parser.add_argument('--output', type=str, default='working_ips.txt',
                        help='Output file for working IPs (default: working_ips.txt)')
    parser.add_argument('--vless', action='store_true',
                        help='Generate VLESS config URLs for found IPs')
    parser.add_argument('--host', type=str, default='d3ub1fvy78o8cz.cloudfront.net',
                        help='WebSocket host for VLESS config')
    
    args = parser.parse_args()
    
    print(f"""
{Colors.BOLD}{Colors.CYAN}╔═══════════════════════════════════════════╗
║     CloudFront IP Scanner v1.0            ║
║     SNI: {args.sni:<20}            ║
╚═══════════════════════════════════════════╝{Colors.RESET}
    """)
    
    working_ips = []
    
    if args.file:
        # Scan IPs from file
        try:
            with open(args.file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            print(f"{Colors.CYAN}[*] Loaded {len(ips)} IPs from {args.file}{Colors.RESET}")
            working_ips = scan_ips(ips, args.workers, args.sni)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading file: {e}{Colors.RESET}")
            sys.exit(1)
            
    elif args.range:
        # Scan specific range
        working_ips = scan_range_full(args.range, args.workers, args.sni)
        
    elif args.quick:
        # Quick scan - sample from all ranges
        ranges = get_cloudfront_ranges()
        if not ranges:
            print(f"{Colors.YELLOW}[!] Using fallback ranges{Colors.RESET}")
            ranges = FALLBACK_RANGES
        
        ips = generate_ips_from_ranges(ranges, args.samples)
        print(f"{Colors.CYAN}[*] Quick scan: {len(ips)} sampled IPs{Colors.RESET}")
        working_ips = scan_ips(ips, args.workers, args.sni)
        
    else:
        parser.print_help()
        print(f"\n{Colors.YELLOW}[!] Please specify --quick, --range, or --file{Colors.RESET}")
        sys.exit(1)
    
    # Results summary
    print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Scan complete! Found {len(working_ips)} working IPs{Colors.RESET}")
    
    if working_ips:
        save_results(working_ips, args.output)
        
        if args.vless:
            print(f"\n{Colors.CYAN}[*] VLESS Configs:{Colors.RESET}")
            vless_file = args.output.replace('.txt', '_vless.txt')
            with open(vless_file, 'w') as f:
                for r in working_ips:
                    config = generate_vless_config(r['ip'], args.host)
                    print(config)
                    f.write(config + '\n')
            print(f"\n{Colors.GREEN}[+] VLESS configs saved to {vless_file}{Colors.RESET}")
    
    return working_ips

if __name__ == "__main__":
    main()
