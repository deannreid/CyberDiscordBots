import asyncio
from datetime import datetime
from wazuhRunner import fncSendWazuhAlert, bot
import discrdConfig

alert = {
    "agent": "XHSMERLINUKN01-NPD_TEST",
    "rule": "FIM: Unauthorized File Change",
    "description": "Detected modification of /etc/passwd",
    "severity": "High",
    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    "rule_id": 1002,
    "location": "/etc/passwd",
    "srcip": "10.0.0.5",
    "srcport": 22,
    "user": "root",
    "decoder": {"name": "syscheck"},
    "group": ["syscheck", "fim"],
    "full_log": "File integrity checksum mismatch for /etc/passwd"
}

@bot.event
async def on_ready():
    print(f"🤖 Bot is ready for test as {bot.user.name}")
    await fncSendWazuhAlert(alert)
    await asyncio.sleep(3)
    await bot.close()

asyncio.run(bot.start(discrdConfig.DISCORD_APIKEY))