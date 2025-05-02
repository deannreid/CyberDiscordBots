# Prefix used to invoke commands in Discord (e.g., '!help')
COMMAND_PREFIX = '!'


# Base URL for accessing the NIST NVD API
NIST_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='

# URL for the Microsoft Security Response Center (MSRC) RSS feed (used for Patch Tuesday updates)
MSFT_FEEDURL = 'https://api.msrc.microsoft.com/update-guide/rss'

# OpenAI API endpoint for using GPT models (e.g., for summarising CVEs, auto-tagging, etc.)
OPENAI_API = 'https://api.openai.com/v1/completions'








# Discord channel ID where CVE alerts will be posted
CVE_CHANNEL_ID =   ####################

# Discord channel ID for general cybersecurity news and updates
NEWS_CHANNEL_ID =  ####################

# Discord channel ID specifically for Patch Tuesday notifications from Microsoft
#PTUES_CHANNEL_ID = ####################

# Discord channel ID for posting proof-of-concept (PoC) exploit discussions or links
#POCS_CHANNEL_ID =  ####################

# Discord channel ID for posting statistics from pfSense or other firewall/network data
#PFSTATS_CHANNEL_ID = ####################

# Discord channel ID used for posting bot or system status updates (e.g., 'Bot is online')
STATUS_CHANNEL_ID = ####################




CVE_TRACK_FILE = 'posted_cves.txt'



#####                                      #####
## Probably better to move these to .env file ##
#####                                      #####

# Discord bot token used to authenticate with the Discord API (keep this secret)
DISCORD_APIKEY = ''

# API key used to authenticate with OpenAI (must be kept secret and secure)
OPENAI_APIKEY  = ''

# API key used to authenticate with the NIST API (replace or load securely in production)
NIST_APIKEY    = ''