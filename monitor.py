#!/usr/bin/env python3
import os
import sys
import json
import argparse
import requests
import urllib3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Disable insecure requests warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Colorama
init(autoreset=True)

# Global variables
SIGNATURES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures.json")
SIGNATURES = []

def load_signatures():
    global SIGNATURES
    if not os.path.exists(SIGNATURES_FILE):
        print(f"{Fore.RED}[-] Signatures file not found at {SIGNATURES_FILE}")
        sys.exit(1)
    try:
        with open(SIGNATURES_FILE, "r") as f:
            SIGNATURES = json.load(f)
        print(f"{Fore.CYAN}[*] Loaded {len(SIGNATURES)} cloud service signatures.")
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to load signatures: {str(e)}")
        sys.exit(1)

def resolve_cname(domain):
    """
    Resolves the CNAME of a given domain.
    Returns a list of CNAME targets (strings) or None.
    """
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        cnames = [str(rdata.target).rstrip('.') for rdata in answers]
        return cnames
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    except Exception:
        return None

def send_webhook(webhook_url, message):
    """
    Sends an alert message to a Discord or Telegram webhook.
    """
    if not webhook_url:
        return
    try:
        if "discord.com" in webhook_url:
            data = {"content": message}
            requests.post(webhook_url, json=data, timeout=5)
        elif "api.telegram.org" in webhook_url:
            # Expected format: https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat_id>
            requests.post(webhook_url + f"&text={message}", timeout=5)
    except Exception as e:
        print(f"{Fore.RED}[!] Webhook notification failed: {str(e)}")

def check_takeover(domain, cnames, webhook_url, verbose):
    """
    Checks if any CNAME target matches signatures and validates vulnerability.
    """
    for cname in cnames:
        for provider in SIGNATURES:
            # Check if CNAME contains provider's domain keywords
            match = False
            for key in provider["cname"]:
                if key in cname.lower():
                    match = True
                    break
            
            if match:
                if verbose:
                    print(f"{Fore.YELLOW}[i] Domain {domain} points to {cname} (Matched provider: {provider['name']})")
                
                # Perform HTTP verification
                urls = [f"https://{domain}", f"http://{domain}"]
                for url in urls:
                    try:
                        response = requests.get(url, timeout=6, verify=False, allow_redirects=True)
                        response_text = response.text
                        
                        # Inspect response body for signatures
                        for sig in provider["response"]:
                            if sig.lower() in response_text.lower():
                                alert_msg = (
                                    f"🔥 [VULNERABLE] {domain} -> CNAME: {cname} | Provider: {provider['name']} "
                                    f"| Detected Signature: '{sig}'"
                                )
                                print(f"{Fore.GREEN}{Style.BRIGHT}[+] {alert_msg}")
                                send_webhook(webhook_url, alert_msg)
                                return True
                    except requests.exceptions.RequestException as e:
                        if verbose:
                            print(f"{Fore.RED}[-] HTTP Request failed for {url}: {str(e)}")
                        continue
    return False

def scan_domain(domain, webhook_url, verbose):
    if verbose:
        print(f"{Fore.BLUE}[*] Scanning: {domain}")
    
    cnames = resolve_cname(domain)
    if not cnames:
        if verbose:
            print(f"{Fore.LIGHTBLACK_EX}[-] No CNAME found for {domain}")
        return None
    
    is_vuln = check_takeover(domain, cnames, webhook_url, verbose)
    if not is_vuln and verbose:
        print(f"{Fore.LIGHTBLACK_EX}[-] Checked {domain} (CNAME: {', '.join(cnames)}) - Clean.")
    return domain, cnames, is_vuln

def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Monitor - Elite Hunting Tool")
    parser.add_argument("-d", "--domain", help="Single domain/subdomain to scan")
    parser.add_argument("-l", "--list", help="File containing list of subdomains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-w", "--webhook", help="Webhook URL for Slack/Discord alerts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)
        
    load_signatures()
    
    domains = []
    if args.domain:
        domains.append(args.domain.strip())
    elif args.list:
        if not os.path.exists(args.list):
            print(f"{Fore.RED}[-] Domains list file not found: {args.list}")
            sys.exit(1)
        with open(args.list, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
            
    print(f"{Fore.CYAN}[*] Loaded {len(domains)} targets for scanning...")
    
    # ThreadPool execution
    print(f"{Fore.CYAN}[*] Starting scanning with {args.threads} threads...")
    print(f"{Fore.WHITE}{'-'*60}")
    
    vuln_count = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_domain, d, args.webhook, args.verbose): d for d in domains}
        for future in as_completed(futures):
            res = future.result()
            if res and res[2]:  # If vulnerable is True
                vuln_count += 1
                
    print(f"{Fore.WHITE}{'-'*60}")
    print(f"{Fore.CYAN}[*] Scan completed. Total targets: {len(domains)} | Found vulnerable: {vuln_count}")

if __name__ == "__main__":
    main()
