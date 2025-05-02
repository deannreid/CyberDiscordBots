# 🛡️ CyberSec Discord Automation Suite (Discord of Things)

A modular collection of Discord bots for automating cybersecurity awareness, vulnerability tracking, and PoC alerting — tailored for security teams, blue teams, and researchers.

## 🔧 Overview

This repo contains purpose-built Discord bots that integrate with public CVE sources, enrich vulnerability data, and push it into designated channels. Bots are modular and can be run independently or together depending on your needs.

---

## 🤖 Bots Included

### 🔔 `Tool Post Bot`

Generates OpenAI-powered introductions for GitHub security tools.

* Commands:

  * `!newtool <github_repo_url>` — generates a rich embed describing the tool.
  * `!postreadme <url>` — fetches and posts README content from GitHub.

![image](https://github.com/user-attachments/assets/53a05e16-dc96-4277-985b-fb83dce0e61b)

![image](https://github.com/user-attachments/assets/fd472f55-9fd6-4ce8-aa47-891c83debff0)

---

### 🩻 `Patch Tuesday Bot`

Fetches Microsoft Patch Tuesday CVEs from MSRC RSS and enriches them using NIST's CVE API.

* Posts a monthly CVE digest to a dedicated Patch Tuesday channel.
* Embeds include CVSS scores, CWE, vector, and references.
* Throttled to respect NIST API rate limits.

![image](https://github.com/user-attachments/assets/cd5ad7fc-d694-4322-95e0-b38e2b2d2128)

---

### 🧪 `PoC Feed Bot`

Fetches exploitable CVEs from [Kevin](https://kevin.gtfkd.com/kev) feed and posts alerts when public PoCs are found.

* Filters previously posted PoCs using a track file.
* Extracts and displays:

  * GitHub PoC links
  * Threat actor info
  * Industry impact
  * Ransomware campaign use

![image](https://github.com/user-attachments/assets/276b2640-57f6-4220-961e-4aae59c6f904)
![image](https://github.com/user-attachments/assets/509f17a0-844e-4074-a40a-e850e33c8f27)

---

## 📦 File Structure

```bash
.
├── cveBot.py         # Tracks and posts CVEs
├── cveNews.py         # Tracks and posts latest Cyber News
├── newTools.py         # Handles GitHub tool promotion via OpenAI
├── patchTuesday.py     # Fetches, tracks and posts Microsoft Patch Tuesday CVEs
├── latestPocs.py          # Tracks and posts CVEs with public PoCs from KEV feed
├── discrdConfig.py        # All config variables, keys, tokens, and channel IDs # Recommend moving API keys to .env
├── posted_cves.txt        # Track file for posted CVEs (Patch Tuesday) - Automatically Created on first run
├── posted_news.txt        # (Optional) for any news-based bot - Automatically Created on first run
├── posted_pocs.txt        # Track file for posted PoCs - Automatically Created on first run
└── README.md              # << You are Here >>
```

---

## 🔐 Configuration

All credentials and channel IDs are stored in `discrdConfig.py`:

```python
# === Discord Bot Configuration ===

COMMAND_PREFIX = '!'

NIST_API_URL   = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
MSFT_FEEDURL   = 'https://api.msrc.microsoft.com/update-guide/rss'
NEWS_FEED_URL  = 'https://cvefeed.io/rssfeed/newsroom.atom'
OPENAI_API     = 'https://api.openai.com/v1/completions'

CVE_TRACK_FILE       = 'posted_cves.txt'
NEWS_TRACK_FILE      = 'posted_news.txt'
PATCHTUES_TRACK_FILE = 'msft_ptues_cves.txt'
POC_TRACK_FILE       = 'posted_pocs.txt'


# Discord Channel IDs (replace with actual values)

STATUS_CHANNEL_ID  = ####################  # Status updates

# Optional (uncomment and assign as needed)
# PTUES_CHANNEL_ID   = ####################  # Patch Tuesday alerts
# POCS_CHANNEL_ID    = ####################  # Proof-of-Concept discussions
# PFSTATS_CHANNEL_ID = ####################  # pfSense / firewall stats
# NEWS_CHANNEL_ID    = ####################  # News updates
# CVE_CHANNEL_ID     = ####################  # CVE alerts

DISCORD_APIKEY = ''      # Discord bot token
OPENAI_APIKEY  = ''      # OpenAI API key
NIST_APIKEY    = ''      # NIST API key
```

> 💡 *Recommended: Migrate these into a `.env` file in production.*

---

## 🧪 Requirements

* Python 3.9+
* Discord.py
* aiohttp
* feedparser
* BeautifulSoup (for HTML parsing)
* OpenAI SDK (`openai`)
* Requests

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## ⏱️ Task Schedules

* `Patch Tuesday Bot`: runs every 24h
* `PoC Feed Bot`: polls every 30 minutes
* `Tool Post Bot`: manually invoked via commands

Included Linux System Files for autostart

---

## 📣 Attribution

Developed by Sasquatch Inc LTD plc
Crafted for red and blue teams who appreciate tidy automation with some AI spice.

---
