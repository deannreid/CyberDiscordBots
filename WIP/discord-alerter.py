#!/usr/bin/env python3

import sys
import json
import socket
import os
from datetime import datetime
import discrdConfig

def fncReadWazuhAlert():
    try:
        raw_input = sys.stdin.read()
        alert_data = json.loads(raw_input)
        if isinstance(alert_data, dict) and "parameters" in alert_data and "alert" in alert_data["parameters"]:
            return alert_data["parameters"]["alert"]
        return alert_data
    except Exception as e:
        if discrdConfig.DEBUG_OUTPUT:
            print(f"❌ Failed to parse alert from stdin: {e}")
        fncPrintStatus("failure", f"JSON parsing error: {str(e)}")
        return None

def fncSendToDiscordSocket(alert):
    try:
        if not os.path.exists(discrdConfig.SOCKET_PATH):
            msg = "Socket not found. Is the Discord bot running?"
            if discrdConfig.DEBUG_OUTPUT:
                print(f"❌ {msg}")
            fncPrintStatus("failure", msg)
            return
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(discrdConfig.SOCKET_PATH)
        client.send(json.dumps(alert).encode())
        client.close()
        if discrdConfig.DEBUG_OUTPUT:
            print("✅ Alert sent to Discord socket.")
        fncPrintStatus("success", "Alert successfully sent to Discord bot socket.")
    except Exception as e:
        if discrdConfig.DEBUG_OUTPUT:
            print(f"❌ Failed to send alert to socket: {e}")
        fncPrintStatus("failure", f"Socket send error: {str(e)}")

def fncPrintStatus(result, msg=""):
    if not getattr(discrdConfig, "DEBUG_OUTPUT", False):
        return
    status = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": "discord-alert",
        "status": result,
        "msg": msg
    }
    print(json.dumps(status))

if __name__ == "__main__":
    alert = fncReadWazuhAlert()
    if alert:
        fncSendToDiscordSocket(alert)
