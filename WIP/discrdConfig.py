# === Discord Bot Configuration ===

# Command prefix used for invoking bot commands
COMMAND_PREFIX = '!'
DEBUG_ENABLE = true

# API Endpoints
NIST_API_URL   = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
MSFT_FEEDURL   = 'https://api.msrc.microsoft.com/update-guide/rss'
NEWS_FEED_URL  = 'https://cvefeed.io/rssfeed/newsroom.atom'
OPENAI_API     = 'https://api.openai.com/v1/completions'

# File paths for tracking posted content
CVE_TRACK_FILE       = 'posted_cves.txt'
NEWS_TRACK_FILE      = 'posted_news.txt'
PATCHTUES_TRACK_FILE = "msft_ptues_cves.txt"
POC_TRACK_FILE       = 'posted_pocs.txt'

SOCKET_PATH = "/tmp/wazuh_discord_alert.sock"

# Discord Channel IDs (replace with actual values)

STATUS_CHANNEL_ID  = ####################  # Status updates

# Optional (uncomment and assign as needed)
# PTUES_CHANNEL_ID   = ####################  # Patch Tuesday alerts
# POCS_CHANNEL_ID    = ####################  # Proof-of-Concept discussions
# PFSTATS_CHANNEL_ID = ####################  # pfSense / firewall stats
# NEWS_CHANNEL_ID    = ####################  # News updates
# CVE_CHANNEL_ID     = ####################  # CVE alerts

# === Wazuh Config === #
# Optional (uncomment and assign as needed)
#MALWARE_DETECTIONS_ID = ####################
#FIM_ALERTS_ID         = ####################
#THREAT_HUNTING_ID     = ####################
#WAZUH_MONITORING_ID   = ####################
#WAZUH_ALERTS_ID       = ####################

# Secrets (⚠️ should ideally be managed via environment variables or a secrets manager)
DISCORD_APIKEY = ''      # Discord bot token
OPENAI_APIKEY  = ''      # OpenAI API key
NIST_APIKEY    = ''      # NIST API key