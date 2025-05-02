# === Patch Tuesday CVE Discord Bot ===
#
# Automatically fetches, parses, and posts monthly Microsoft Patch Tuesday CVEs
# with enriched data from NIST's API into a designated Discord channel.

import requests
import xml.etree.ElementTree as ET
import os
import time
from datetime import datetime
import asyncio
import discord
from discord.ext import tasks, commands
import discrdConfig

# === Bot Setup ===
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
bot = commands.Bot(command_prefix=discrdConfig.COMMAND_PREFIX, intents=intents)

# === Utility: Status Messaging ===
async def fncSendStatusMessage(msg):
    channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
    if channel:
        try:
            await channel.send(f"🛡️ **Status Update:** {msg}")
        except discord.HTTPException as e:
            print(f"[Status] ❌ Failed: {e}")

# === File Helpers ===
def fncLoadCVEs(path):
    return set(open(path, 'r', encoding='utf-8').read().splitlines()) if os.path.exists(path) else set()

def fncSaveNewCVEs(cves, path):
    existing = fncLoadCVEs(path)
    new = [cve for cve in cves if cve not in existing]
    if not new:
        print("⚠️ No new CVEs found.")
        return False
    with open(path, 'a', encoding='utf-8') as f:
        for cve in new:
            f.write(cve + '\n')
            print(f"✅ Added: {cve}")
    return True

# === RSS Parsing ===
def fncFetchRSS(url):
    try:
        return requests.get(url, timeout=10).text
    except requests.RequestException as e:
        print(f"❌ RSS fetch error: {e}")
        return None

def fncExtractCVEs(xml):
    try:
        root = ET.fromstring(xml)
        this_month = datetime.now().month
        this_year = datetime.now().year
        cves = []
        for item in root.findall(".//item"):
            pub_date = item.findtext("pubDate", default="").replace(" Z", "")
            try:
                dt = datetime.strptime(pub_date, "%a, %d %b %Y %H:%M:%S")
                if dt.year == this_year and dt.month == this_month:
                    guid = item.findtext("guid", default="").strip()
                    if guid.startswith("CVE-"):
                        cves.append(guid)
            except Exception:
                continue
        return cves
    except ET.ParseError as e:
        print(f"❌ XML parse error: {e}")
        return []

# === NIST API & Parsing ===
nist_count = 0

def fncNISTRequest(endpoint, params=None, retries=3):
    global nist_count
    headers = {
        "Authorization": "apiKey:" + discrdConfig.NIST_APIKEY,
        "Accept": "application/json",
        "User-Agent": "PTBot/1.0"
    }
    url = f"https://services.nvd.nist.gov/rest/json/{endpoint.lstrip('/')}"

    if nist_count >= 5:
        print("⏳ Sleeping 45s for NIST rate limit...")
        time.sleep(45)
        nist_count = 0

    for attempt in range(retries):
        try:
            res = requests.get(url, headers=headers, params=params)
            if res.status_code == 403:
                print(f"403 Forbidden. Retrying...")
                time.sleep((attempt + 1) * 15)
                continue
            res.raise_for_status()
            nist_count += 1
            return res.json()
        except Exception as e:
            print(f"❌ NIST error: {e}")
            time.sleep(10)
    return None

def fncParseNIST(data):
    vulns = data.get("vulnerabilities", [])
    result = []
    for v in vulns:
        cve = v.get("cve", {})
        cvss = next((m.get("cvssData", {}) for m in cve.get("metrics", {}).get("cvssMetricV31", [])), {})
        result.append({
            "id": cve.get("id", "N/A"),
            "desc": next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A"),
            "sev": cvss.get("baseSeverity", "N/A"),
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A"),
            "cwe": next((d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("lang") == "en"), "N/A"),
            "refs": [r.get("url") for r in cve.get("references", [])],
            "published": cve.get("published", "N/A")
        })
    return result

# === Discord Embed Helpers ===
def fncColor(sev):
    return {
        "CRITICAL": discord.Color.red(),
        "HIGH": discord.Color.orange(),
        "MEDIUM": discord.Color.gold(),
        "LOW": discord.Color.green()
    }.get(sev.upper(), discord.Color.dark_grey())

async def fncFetchCVEData(cve_id):
    data = await asyncio.to_thread(fncNISTRequest, "cves/2.0", {"cveId": cve_id})
    parsed = await asyncio.to_thread(fncParseNIST, data) if data else []
    return parsed[0] if parsed else None

async def fncPostToDiscord(cves):
    ch = bot.get_channel(discrdConfig.PTUES_CHANNEL_ID)
    if not ch:
        print("❌ Channel not found.")
        return

    month = datetime.now().strftime("%B")
    await ch.send(f"```\n===       {month} Patch Tuesday       ===\n```")

    for cve in cves:
        data = await fncFetchCVEData(cve)
        if not data:
            continue

        embed = discord.Embed(
            title=f"🛠 Patch Tuesday - {data['id']}",
            url=f"https://nvd.nist.gov/vuln/detail/{data['id']}",
            color=fncColor(data['sev'])
        )
        embed.add_field(name="🧠 Description", value=data['desc'][:1024], inline=False)
        embed.add_field(name="📊 Severity & Score", value=f"{data['sev']} | CVSS {data['score']}", inline=True)
        embed.add_field(name="🧬 Vector", value=data['vector'], inline=True)
        embed.add_field(name="🔖 CWE", value=data['cwe'], inline=False)
        if data['refs']:
            refs = "\n".join(f"🔗 {r}" for r in data['refs'][:5])
            embed.add_field(name="📚 References", value=refs, inline=False)
        embed.set_footer(text=f"Published: {data['published']}")

        try:
            await ch.send(embed=embed)
            print(f"✅ Posted: {data['id']}")
        except Exception as e:
            print(f"❌ Post error: {e}")
        await asyncio.sleep(1.5)

# === Bot Events ===
@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user.name}")
    await fncSendStatusMessage("\n=============== \n PTUES Bot started successfully! \n ===============")
    await fncSendStatusMessage("🤖 Monitoring for Patch Tuesday CVEs.")
    check_patch_tuesday_feed.start()

last_posted = None

@tasks.loop(hours=24)
async def check_patch_tuesday_feed():
    global last_posted
    print("🔍 Checking Patch Tuesday feed...")
    xml = fncFetchRSS(discrdConfig.MSFT_FEEDURL)
    if not xml:
        await fncSendStatusMessage("❌ Failed to fetch RSS feed.")
        return

    cves = fncExtractCVEs(xml)
    await fncSendStatusMessage(f"📥 Fetched {len(cves)} CVEs from the Patch Tuesday feed.")

    if not cves:
        await fncSendStatusMessage("⚠️ No CVEs found in feed.")
        return

    existing = fncLoadCVEs(discrdConfig.PATCHTUES_TRACK_FILE)
    new_cves = list(set(cves) - existing)
    updated = fncSaveNewCVEs(cves, discrdConfig.PATCHTUES_TRACK_FILE)

    if new_cves:
        now_month = datetime.now().month
        if last_posted != now_month:
            last_posted = now_month
        await fncPostToDiscord(new_cves)
    else:
        await fncSendStatusMessage("✅ No new Patch Tuesday updates today.")

    await fncSendStatusMessage("🕐 PTUES Bot Waiting 24 hours for next scan...")

# === Run Bot ===
bot.run(discrdConfig.DISCORD_APIKEY)
