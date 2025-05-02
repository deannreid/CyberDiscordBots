import discord
from discord.ext import commands, tasks
import feedparser
import asyncio
import os
import html
import re
import discrdConfig

# Define the intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

# Initialize the bot with the specified intents
bot = commands.Bot(command_prefix=discrdConfig.COMMAND_PREFIX, intents=intents)

posted_news = set()

# === Utility Functions ===
def fncLoadPostedNews():
    if os.path.exists(discrdConfig.NEWS_TRACK_FILE):
        with open(discrdConfig.NEWS_TRACK_FILE, 'r') as file:
            return set(file.read().split())
    return set()

def fncSavePostedNews(news_id):
    with open(discrdConfig.NEWS_TRACK_FILE, 'a') as file:
        file.write(news_id + '\n')

def fncCleanHTML(raw_html, is_patch_tuesday):
    text = re.sub(r'<h3>.*?</h3>', '', raw_html, flags=re.DOTALL)
    text = html.unescape(text)
    text = re.sub(r'<a [^>]*>Read more</a>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<a href="([^"]+)"[^>]*>(.*?)</a>', lambda m: f"[{m.group(2)}]({m.group(1)})", text)
    text = re.sub(r'(<strong>Published Date:</strong>|Published Date:)', '**Published Date:**', text)

    if is_patch_tuesday:
        text = re.sub(r'(CVE-\d{4}-\d{4,7})', r'[**\1**](https://msrc.microsoft.com/update-guide/vulnerability/\1)', text)
    else:
        text = re.sub(r'(CVE-\d{4}-\d{4,7})', r'[**\1**](https://nvd.nist.gov/vuln/detail/\1)', text)

    text = re.sub(r'<[^>]+>', '', text)
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    return '\n'.join(lines)

def fncSplitMessage(message, max_length=2000):
    lines = message.split('\n')
    messages = []
    current_message = ''
    for line in lines:
        if len(current_message) + len(line) + 1 > max_length:
            messages.append(current_message)
            current_message = line
        else:
            current_message += '\n' + line if current_message else line
    if current_message:
        messages.append(current_message)
    return messages

async def fncSendStatusMessage(status_message):
    channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
    if channel:
        await channel.send(f"\U0001F6E1️ **Status Update:** {status_message}")

# === Bot Events ===
@bot.event
async def on_ready():
    global posted_news
    print(f'Logged in as {bot.user.name}')
    posted_news = fncLoadPostedNews()
    await fncSendStatusMessage("\n=============== \n News Bot started successfully! \n ===============")
    print('News Bot has started successfully!')
    check_news_feed.start()

# === News Feed Check Loop ===
@tasks.loop(minutes=30)
async def check_news_feed():
    feed = feedparser.parse(discrdConfig.NEWS_FEED_URL)
    news_channel = bot.get_channel(discrdConfig.NEWS_CHANNEL_ID)

    if not news_channel:
        await fncSendStatusMessage("❌ Error: News channel not found.")
        return

    await fncSendStatusMessage(f"Fetched {len(feed.entries)} news items from the feed.")
    print(f"Fetched {len(feed.entries)} news items from the feed.")

    new_news_count = 0
    total_news_count = len(feed.entries[:25])

    for entry in feed.entries[:25]:
        news_id = entry.id
        if news_id not in posted_news:
            title = entry.title
            link = entry.link
            is_patch_tuesday = 'Patch Tuesday' in title
            description = fncCleanHTML(entry.summary, is_patch_tuesday)

            if is_patch_tuesday:
                title = f"⚠ - {title} - ⚠"

            message = f"**--------------------------------------------**\n**{title}**\n{description}\nRead more: [here]({link})"
            messages = fncSplitMessage(message)

            for msg in messages:
                await news_channel.send(msg)
                await asyncio.sleep(1)

            posted_news.add(news_id)
            fncSavePostedNews(news_id)
            new_news_count += 1

    await fncSendStatusMessage(f"✅ Posted {new_news_count} new news items out of {total_news_count} fetched.")
    print(f"✅ Posted {new_news_count} new news items out of {total_news_count} fetched.")

# === Run Bot ===
bot.run(discrdConfig.DISCORD_APIKEY)
