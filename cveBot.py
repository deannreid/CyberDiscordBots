import discord
from discord.ext import commands, tasks
import feedparser
import asyncio
import os
import html
import re
import aiohttp
from datetime import datetime
import discrdConfig

# Define the intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

# Initialize the bot
bot = commands.Bot(command_prefix=discrdConfig.COMMAND_PREFIX, intents=intents)

posted_cves = set()

# === Utility Functions ===
def fncLoadPostedCVE():
    if os.path.exists(discrdConfig.CVE_TRACK_FILE):
        with open(discrdConfig.CVE_TRACK_FILE, 'r') as file:
            return set(line.strip().split('/')[-1] for line in file if line.strip())
    return set()

def fncSavePostedCVE(cve_id):
    with open(discrdConfig.CVE_TRACK_FILE, 'a') as file:
        file.write(cve_id + '\n')

def fncTruncateField(value, max_len=1024):
    return value if len(value) <= max_len else value[:max_len - 3] + "..."

def fncCleanHTML(raw_html):
    text = html.unescape(raw_html)
    text = text.replace('<br />', '\n')
    text = re.sub(r'<strong>(.*?)</strong>', r'**\1**', text)
    text = re.sub(r'<[^>]+>', '', text)
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    return '\n'.join(lines)

async def fncSendStatusMessage(status_message):
    channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
    if channel:
        try:
            await channel.send(f"\U0001F6E1️ **Status Update:** {status_message}")
        except discord.HTTPException as e:
            print(f"Failed to send status message: {e}")

async def fncFetchNISTData(cve_id):
    headers = {"apiKey": discrdConfig.NIST_APIKEY}
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(discrdConfig.NIST_API_URL + cve_id) as response:
                if response.status == 200:
                    data = await response.json()
                    vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
                    metrics = vuln.get("metrics", {})
                    vector = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", "N/A")
                    score = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                    severity = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A")
                    cwe = vuln.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A")
                    references = [ref.get("url") for ref in vuln.get("references", [])]
                    return vector, score, severity, cwe, references
        except Exception as e:
            print(f"Error fetching NIST data for {cve_id}: {e}")
    return "N/A", "N/A", "N/A", "N/A", []

# === Bot Events ===
@bot.event
async def on_ready():
    global posted_cves
    print(f'Logged in as {bot.user.name}')
    posted_cves = fncLoadPostedCVE()
    await fncSendStatusMessage("\n=============== \n CVE Bot started successfully! \n ===============")
    check_cve_feed.start()

# === CVE Feed Check Loop ===
@tasks.loop(minutes=30)
async def check_cve_feed():
    feed_url = 'https://cvefeed.io/rssfeed/latest.atom'
    feed = feedparser.parse(feed_url)
    cve_channel = bot.get_channel(discrdConfig.CVE_CHANNEL_ID)

    if not cve_channel:
        print("\u274C Error: CVE channel not found.")
        await fncSendStatusMessage("\u274C Error: CVE channel not found.")
        return

    total_fetched = len(feed.entries)
    print(f"\U0001F4E5 Fetched {total_fetched} entries from the feed.")
    await fncSendStatusMessage(f"\U0001F4E5 Fetched {total_fetched} CVEs from the feed.")

    new_cves_count = 0

    for entry in feed.entries[:25]:
        link = entry.get('link', 'No Link').strip()
        cve_id = entry.get('id', 'Unknown CVE').split('/')[-1]
        title = entry.get('title', 'No Title')
        summary_raw = entry.get('summary', '')

        if cve_id not in posted_cves:
            try:
                published_date = datetime.strptime(entry.get('published', ''), "%Y-%m-%dT%H:%M:%S.%f%z")
                published_str = published_date.strftime("%B %d, %Y, %I:%M %p UTC")
            except Exception:
                published_str = entry.get('published', 'N/A')

            description = fncCleanHTML(summary_raw)
            description_text = re.sub(r'CVE ID\s*:\s*.*', '', description, flags=re.IGNORECASE)
            description_text = re.sub(r'Published\s*:\s*.*', '', description_text, flags=re.IGNORECASE)
            description_text = re.sub(r'Severity\s*:\s*.*', '', description_text, flags=re.IGNORECASE)
            description_text = re.sub(r'Visit the link.*', '', description_text, flags=re.IGNORECASE)
            description_text = description_text.strip()

            vector, cvss_score, severity, cwe, references = await fncFetchNISTData(cve_id)

            if severity == "CRITICAL":
                colour = discord.Color.red()
            elif severity == "HIGH":
                colour = discord.Color.orange()
            elif severity == "MEDIUM":
                colour = discord.Color.gold()
            elif severity == "LOW":
                colour = discord.Color.green()
            else:
                colour = discord.Color.dark_grey()

            embed = discord.Embed(title=f"\U0001F6E1️ {title}", color=colour)
            embed.add_field(name="\U0001F4DC Summary", value=(
                f"\U0001F4DF **[{cve_id}]({link})**\n"
                f"\U0001F4C5 Published: {published_str}\n"
                f"\U0001F9E0 Description: {fncTruncateField(description_text)}\n"
                f"\u26A0️ Severity: `{severity}` | CVSS: `{cvss_score}`\n"
                f"\U0001F52C Vector: `{vector}` | CWE: `{cwe}`"
            ), inline=False)

            if references:
                reference_text = "\n".join(f"🔗 {url}" for url in references)
                embed.add_field(name="\U0001F517 References", value=fncTruncateField(reference_text), inline=False)
            else:
                embed.add_field(name="\U0001F517 Reference", value=link, inline=False)

            try:
                await cve_channel.send(embed=embed)
                posted_cves.add(cve_id)
                fncSavePostedCVE(cve_id)
                new_cves_count += 1
                print(f"\u2705 Posted CVE: {cve_id} — {title}")
                await asyncio.sleep(1)
            except discord.Forbidden:
                print(f"\u274C Permission Denied: Cannot send to {cve_channel.name}")
                await fncSendStatusMessage(f"\u274C Permission Denied: Cannot send to {cve_channel.name}")
            except discord.HTTPException as e:
                print(f"\u274C HTTP Error: {e}")
                await fncSendStatusMessage(f"\u274C HTTP Error while sending message: {e}")

    print(f"\u2705 Posted {new_cves_count} new CVEs out of {total_fetched} fetched.")
    await fncSendStatusMessage(f"\u2705 Posted {new_cves_count} new CVEs out of {total_fetched} fetched.")
    print("\U0001F552 Waiting 30 minutes before the next scan...")
    await fncSendStatusMessage("\U0001F552 Waiting 30 minutes before the next scan...")

# === Test Command ===
@bot.command()
async def test(ctx):
    try:
        await ctx.send("Testing permissions!")
    except discord.Forbidden:
        await ctx.send("I do not have permission to send messages in this channel.")

# === Run Bot ===
bot.run(discrdConfig.DISCORD_APIKEY)
