#!/usr/bin/env python3

import os
import sys
import json
import asyncio
import socket
import discord
from discord.ext import commands
from datetime import datetime
import discrdConfig

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def fncReadAlert():
    try:
        raw_input = sys.stdin.read()
        alert = json.loads(raw_input)
        if isinstance(alert, dict) and "parameters" in alert and "alert" in alert["parameters"]:
            return alert["parameters"]["alert"]
        return alert
    except Exception as e:
        print(f"\u274c Failed to parse stdin: {e}")
        return None

def fncSendToSocket(data):
    try:
        if not os.path.exists(discrdConfig.SOCKET_PATH):
            print("\u274c Socket not found, is the bot running?")
            return
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(discrdConfig.SOCKET_PATH)
        client.send(json.dumps(data).encode())
        client.close()
    except Exception as e:
        print(f"\u274c Failed to send alert to socket: {e}")

async def fncSendStatusUpdate(event: str, extra: str = ""):
    try:
        channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
        if not channel:
            return
        embed = discord.Embed(
            title="\ud83d\udce3 Wazuh Discord Bot Status",
            description=event,
            color=discord.Color.teal()
        )
        embed.add_field(name="\ud83d\udd52 Timestamp", value=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), inline=False)
        if extra:
            embed.add_field(name="\ud83d\udce6 Details", value=extra, inline=False)
        await channel.send(embed=embed)
    except Exception as e:
        print(f"\u274c Failed to send status update: {e}")

async def fncSendWazuhAlert(alert):
    rule = alert.get('rule', '').lower()
    severity = alert.get('severity', 'Low')
    agent = alert.get('agent', 'Unknown')
    description = alert.get('description', 'No description provided.')
    timestamp = alert.get('timestamp', 'Unknown')
    rule_id = str(alert.get('rule_id', 'N/A'))
    location = alert.get('location', 'N/A')
    src_ip = alert.get('srcip', 'N/A')
    src_port = str(alert.get('srcport', 'N/A'))
    user = alert.get('user', 'N/A')
    decoder = alert.get('decoder', {}).get('name', 'N/A')
    groups = ', '.join(alert.get('group', [])) if alert.get('group') else 'N/A'
    full_log = alert.get('full_log', '')

    if len(full_log) > 1024:
        full_log = full_log[:1021] + "..."

    decoder_name = alert.get('decoder', {}).get('name', '').lower()
    rule_lower = rule.lower()

    if any(x in rule_lower or x in decoder_name for x in ['malware', 'virus', 'trojan', 'ransomware']):
        channel_id = discrdConfig.MALWARE_DETECTIONS_ID
    elif any(x in rule_lower or x in decoder_name for x in ['fim', 'file integrity', 'unauthorized file', 'syscheck']):
        channel_id = discrdConfig.FIM_ALERTS_ID
    elif any(x in rule_lower or x in decoder_name for x in ['suspicious', 'recon', 'brute', 'hunt', 'lateral']):
        channel_id = discrdConfig.THREAT_HUNTING_ID
    elif any(x in rule_lower or x in decoder_name for x in ['agent disconnected', 'ossec', 'manager']):
        channel_id = discrdConfig.WAZUH_MONITORING_ID
    else:
        channel_id = discrdConfig.WAZUH_ALERTS_ID

    color_map = {
        "Low": discord.Color.green(),
        "Medium": discord.Color.gold(),
        "High": discord.Color.orange(),
        "Critical": discord.Color.red()
    }

    embed = discord.Embed(
        title=f"\ud83d\udea8 {alert.get('rule', 'Alert')}",
        description=description,
        color=color_map.get(severity, discord.Color.greyple())
    )

    embed.add_field(name="\ud83d\udcbb Agent", value=agent, inline=True)
    embed.add_field(name="\u26a0\ufe0f Severity", value=severity, inline=True)
    embed.add_field(name="\ud83c\udd94 Rule ID", value=rule_id, inline=True)
    embed.add_field(name="\ud83d\udcc1 Location", value=location, inline=True)
    embed.add_field(name="\ud83c\udf10 Source IP", value=src_ip, inline=True)
    embed.add_field(name="\ud83d\udd0c Source Port", value=src_port, inline=True)
    embed.add_field(name="\ud83d\udc64 User", value=user, inline=True)
    embed.add_field(name="\ud83d\udce6 Decoder", value=decoder, inline=True)
    embed.add_field(name="\ud83c\udff7\ufe0f Groups", value=groups, inline=True)
    if full_log:
        embed.add_field(name="\ud83d\udcdd Log", value=full_log, inline=False)
    embed.set_footer(text=f"\ud83d\udd52 {timestamp}")

    try:
        channel = bot.get_channel(channel_id)
        if channel:
            await channel.send(embed=embed)
            print(f"\u2705 Alert sent to {channel.name}")
            try:
                status_channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
                if status_channel:
                    route_info = f"\ud83d\udce1 Alert routed to <#{channel_id}> from agent `{agent}` with rule `{rule}`"
                    await status_channel.send(route_info)
            except Exception as e:
                print(f"\u26a0\ufe0f Failed to send routing update: {e}")
    except Exception as e:
        await fncSendStatusUpdate("\u274c Failed to route alert", str(e))

async def fncHandleAlerts():
    if os.path.exists(discrdConfig.SOCKET_PATH):
        os.remove(discrdConfig.SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(discrdConfig.SOCKET_PATH)
    server.listen(5)
    server.setblocking(False)

    loop = asyncio.get_running_loop()
    print(f"\U0001f4e1 Listening for alerts on socket: {discrdConfig.SOCKET_PATH}")

    while True:
        client, _ = await loop.sock_accept(server)
        data = await loop.sock_recv(client, 65536)
        client.close()
        try:
            alert = json.loads(data.decode())
            print("\U0001f4e5 Alert received via socket. Dispatching to Discord...")
            await fncSendWazuhAlert(alert)
        except Exception as e:
            await fncSendStatusUpdate("\u274c Failed to process alert", str(e))

@bot.event
async def on_ready():
    print(f"\u2705 SneakyBeakyBot online as {bot.user.name}")
    await fncSendStatusUpdate("\ud83d\udfe2 Bot Online", f"Logged in as `{bot.user.name}`")
    bot.loop.create_task(fncHandleAlerts())

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdin":
        alert_data = fncReadAlert()
        if alert_data:
            fncSendToSocket(alert_data)
    else:
        bot.run(discrdConfig.TOKEN)