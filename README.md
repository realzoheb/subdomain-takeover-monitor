# Subdomain Takeover Monitor 🚀
**A professional, multi-threaded offensive security scanner to detect unclaimed third-party cloud assets and prevent Subdomain Takeovers.**

---

## 📌 Introduction to Subdomain Takeover
A **Subdomain Takeover** occurs when a subdomain points to an external service provider (e.g., GitHub Pages, AWS S3, Heroku, Shopify) via a DNS CNAME record, but the service itself has been deleted or is unclaimed. Attackers can register their own instance on the provider platform using that exact same target address and serve malicious code, steal cookies, or conduct phishing campaigns.

---

## ⚙️ Features
* **Multi-threaded Scanning**: High performance resolution using concurrent Python threads.
* **Deep CNAME Inspection**: Automatically matches targets to 10+ popular cloud services.
* **HTTP Body Signature Verification**: Confirms takeover possibilities by scanning response text against signatures.
* **Alert Notifications**: Supports Telegram, Slack, and Discord webhook integrations for live monitoring.
* **Colorized Interactive Logs**: Clear status separation (`VULNERABLE`, `Clean`, `No CNAME`).

---

## 🛠️ Installation & Setup

1. **Clone the repository & navigate to the directory**:
   ```bash
   git clone https://github.com/realzoheb/subdomain-takeover-monitor.git
   cd subdomain-takeover-monitor
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Guide

Run the script with the `-h` or `--help` flag to see all available arguments:

```bash
python3 monitor.py -h
```

### Options:
* `-d`, `--domain` : Scan a single target subdomain (e.g. `blog.target.com`).
* `-l`, `--list`   : Scan a file containing a list of subdomains (one per line).
* `-t`, `--threads`: Number of concurrent workers (default: 10).
* `-w`, `--webhook`: URL for Slack, Discord, or Telegram webhook alerts.
* `-v`, `--verbose`: Enable detailed scanning logs.

---

## 📝 Usage Examples

### 1. Scan a Single Domain
```bash
python3 monitor.py -d test.example.com -v
```

### 2. Scan a List of Subdomains
Create a file named `subdomains.txt` and populate it, then run:
```bash
python3 monitor.py -l subdomains.txt -t 20
```

### 3. Scan with Real-time Discord/Telegram/Slack Alerts
```bash
python3 monitor.py -l subdomains.txt -w "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
```

---

## 🛡️ Signatures Covered
The tool currently supports scanning for takeover possibilities on:
* GitHub Pages (`github.io`)
* Amazon S3 (`amazonaws.com`)
* Heroku (`herokucdn.com`, `herokuapp.com`)
* Shopify (`myshopify.com`)
* Wix (`wixdns.net`)
* Cargo Collective (`cargocollective.com`)
* Firebase Hosting (`firebaseapp.com`)
* Ghost (`ghost.io`)
* Surge.sh (`surge.sh`)
* Tumblr (`domains.tumblr.com`)
* GitBook (`gitbook.io`)
