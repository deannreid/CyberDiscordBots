# === POC CVE Feed Bot ===
#
# Monitors https://kevin.gtfkd.com/kev for new CVEs with possible public PoCs
# and posts enriched details into a designated Discord channel.

import discord
from discord.ext import commands, tasks
import asyncio
import os
import aiohttp
import re
import html
import urllib.parse
import discrdConfig

# === Bot Setup ===
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
bot = commands.Bot(command_prefix=discrdConfig.COMMAND_PREFIX, intents=intents)

# === Utility Functions ===
def fncLoadPostedPoCs():
    path = discrdConfig.POC_TRACK_FILE
    return set(open(path, 'r').read().split()) if os.path.exists(path) else set()

def fncSavePostedPoC(cve_id):
    with open(discrdConfig.POC_TRACK_FILE, 'a') as f:
        f.write(cve_id + '\n')

def fncTruncate(value, max_len=1024):
    return value if len(value) <= max_len else value[:max_len-3] + '...'

async def fncSendStatus(msg):
    ch = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
    if ch:
        try:
            await ch.send(f"🛡️ **Status Update:** {msg}")
        except Exception as e:
            print(f"[Status] ❌ {e}")

# === Bot Events ===
@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user.name}")
    await fncSendStatus("\n=============== \n PoC Bot started successfully! \n ===============")
    check_kevin_feed.start()

# === Fetch & Post ===
posted_pocs = fncLoadPostedPoCs()

@tasks.loop(minutes=30)
async def check_kevin_feed():
    url = "https://kevin.gtfkd.com/kev"
    channel = bot.get_channel(discrdConfig.POCS_CHANNEL_ID)

    if not channel:
        await fncSendStatus("❌ PoC channel not found.")
        return

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    await fncSendStatus(f"❌ KEV fetch failed: {resp.status}")
                    return
                data = await resp.json()
    except Exception as e:
        await fncSendStatus(f"❌ Exception fetching KEV: {e}")
        return

    vulns = data.get("vulnerabilities", [])[:25]
    count = 0

    for v in vulns:
        cve = v.get("cveID", "N/A")
        if cve in posted_pocs:
            continue

        title = v.get("vulnerabilityName", "Unnamed")
        desc = v.get("shortDescription", "No description.")
        vendor = v.get("vendorProject", "N/A")
        product = v.get("product", "N/A")
        sev = v.get("nvdData", [{}])[0].get("baseSeverity", "Unknown")
        score = v.get("nvdData", [{}])[0].get("baseScore", "N/A")
        exploit = v.get("nvdData", [{}])[0].get("exploitabilityScore", "N/A")
        vector = v.get("nvdData", [{}])[0].get("attackVector", "N/A")
        complexity = v.get("nvdData", [{}])[0].get("attackComplexity", "N/A")
        status = v.get("nvdData", [{}])[0].get("vulnStatus", "N/A")
        refs = [r.get("url") for r in v.get("nvdData", [{}])[0].get("nvdReferences", [])]
        gh_pocs = v.get("githubPocs", [])
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        action = v.get("requiredAction", "No action specified.")
        notes = v.get("notes", "")
        ot_data = v.get("openThreatData", [{}])[0]
        adv = ot_data.get("adversaries", [])
        mal = ot_data.get("malwareFamiles", [])
        ind = ot_data.get("affectedIndustries", [])

        color = {
            "CRITICAL": discord.Color.red(),
            "HIGH": discord.Color.orange(),
            "MEDIUM": discord.Color.gold(),
            "LOW": discord.Color.green(),
            "UNKNOWN": discord.Color.dark_grey()
        }.get(sev.upper(), discord.Color.default())

        embed = discord.Embed(
            title=f"🧪 {title}",
            description=f"**CVE ID:** [{cve}](https://nvd.nist.gov/vuln/detail/{cve})",
            color=color
        )

        embed.add_field(name="Vendor", value=vendor, inline=True)
        embed.add_field(name="Product(s)", value=product, inline=True)
        embed.add_field(name="Severity", value=f"{sev} (Score: {score})", inline=True)
        embed.add_field(name="Exploitability", value=exploit, inline=True)
        embed.add_field(name="Attack Vector", value=f"{vector}, Complexity: {complexity}", inline=True)
        embed.add_field(name="Vulnerability Status", value=status, inline=True)
        embed.add_field(name="Known Ransomware Use", value=ransomware, inline=True)
        embed.add_field(name="Description", value=fncTruncate(desc), inline=False)
        embed.add_field(name="Required Action", value=fncTruncate(action), inline=False)

        poc_block = "\n".join(
            f"🔗 [{url.split('/')[3]}/{url.split('/')[4]}]({url})"
            for url in gh_pocs if len(url.split('/')) >= 5
        ) if gh_pocs else "❌ **🚫 No public PoC available**"
        embed.add_field(name="GitHub PoCs", value=fncTruncate(poc_block), inline=False)

        if refs:
            ref_block = "\n".join(f"📎 [{urllib.parse.urlparse(url).netloc}]({url})" for url in refs)
            embed.add_field(name="References", value=fncTruncate(ref_block), inline=False)

        if notes:
            embed.add_field(name="Notes", value=fncTruncate(notes), inline=False)

        if adv or mal or ind:
            threat = ""
            if adv: threat += f"🔺 **Adversaries:** {', '.join(adv)}\n"
            if mal: threat += f"🧬 **Malware Families:** {', '.join(mal)}\n"
            if ind: threat += f"🏭 **Industries:** {', '.join(ind)}\n"
        else:
            threat = "⚠️ No threat actor data."

        embed.add_field(name="Open Threat Data", value=fncTruncate(threat), inline=False)

        try:
            await channel.send(embed=embed)
            posted_pocs.add(cve)
            fncSavePostedPoC(cve)
            count += 1
            print(f"✅ Posted: {cve}")
            await asyncio.sleep(1)
        except Exception as e:
            await fncSendStatus(f"❌ Failed to post {cve}: {e}")

    await fncSendStatus(f"✅ Posted {count} new PoCs.")
    print(f"✅ Posted {count} new PoCs.")

@bot.command()
async def test(ctx):
    try:
        await ctx.send("Testing permissions!")
    except discord.Forbidden:
        await ctx.send("❌ Missing permission to send messages here.")

# === Run Bot ===
bot.run(discrdConfig.DISCORD_APIKEY)