import asyncio
from datetime import datetime
from wazuhRunner import fncSendWazuhAlert, bot
import discrdConfig

alert = {
    "agent": "XHSMERLINUKN01-NPD",
    "rule": "Suspicious Lateral Movement Tool Detected",
    "description": "Potential use of `impacket-secretsdump` observed on the network.",
    "severity": "Critical",
    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    "rule_id": 4005,
    "location": "/usr/bin/secretsdump.py",
    "srcip": "192.168.0.202",
    "srcport": 58934,
    "user": "pentester",
    "decoder": {"name": "command"},
    "group": ["threat-hunting", "recon"],
    "full_log": "Command execution detected: python3 /usr/bin/secretsdump.py -target 10.0.0.5"
}

@bot.event
async def on_ready():
    print(f"🎯 Bot is ready for Threat Hunting test as {bot.user.name}")
    await fncSendWazuhAlert(alert)
    await asyncio.sleep(3)
    await bot.close()

asyncio.run(bot.start(discrdConfig.DISCORD_APIKEY))