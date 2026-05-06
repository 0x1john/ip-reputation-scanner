# IP Reputation Scanner

A browser-based IP reputation scanner that checks IPs against **VirusTotal**, **AbuseIPDB**, and **Cisco Talos** simultaneously.

**[Live Demo →](https://0x1john.github.io/ip-reputation-scanner)**

## Features

- **Multi-key rotation** — up to 4 API keys per service, auto-switches on rate limit
- **Bulk scanning** — handles 4000+ IPs via a concurrent queue with pause/resume/stop
- **Flexible IP input** — paste IPs separated by comma, space, newline, quotes (`'` `"`) or upload a CSV/TXT file
- **3 services** — VirusTotal, AbuseIPDB, Cisco Talos (link-based, or via CORS proxy)
- **Real-time results** — live table with color-coded reputation scores as scans complete
- **Export** — download results as CSV or JSON
- **No backend** — pure browser tool, API keys stored in localStorage only

## Setup

### 1. Host on GitHub Pages

```bash
git init
git add index.html README.md
git commit -m "Add IP reputation scanner"
git remote add origin https://github.com/0x1john/ip-reputation-scanner.git
git push -u origin main
```

Then go to your repo **Settings → Pages → Source: main branch** and save.

Your tool will be live at `https://0x1john.github.io/ip-reputation-scanner`

### 2. Get API Keys

| Service | Free Tier | Link |
|---------|-----------|------|
| VirusTotal | 4 requests/min | https://www.virustotal.com/gui/user/me/apikey |
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/account/api |
| Cisco Talos | No API key needed | Links provided automatically |

Enter up to **4 keys per service** in the API Keys panel. Keys auto-rotate when rate limits are hit.

## Rate Limits & Bulk Scanning

For 4,000 IPs with 4 VirusTotal keys (free tier, 4 req/min each = 16 req/min total):
- ~250 minutes to complete all VirusTotal checks
- Use **Pause/Resume** to manage the session
- Results export to CSV/JSON at any point

**Recommended settings for bulk scans:**
- Workers: 3
- VT Delay: 15000ms (free tier) or 1000ms (premium)

## Cisco Talos

Talos has no public API. The tool provides a direct link to each IP's Talos page. If you run a CORS proxy (e.g., [corsproxy.io](https://corsproxy.io)), enter the proxy URL in the Cisco Talos section to attempt live reputation fetching.

## Privacy

API keys are stored in your browser's `localStorage` only — nothing is sent to any server other than the three reputation APIs.
