# === Tool Post Bot ===
#
# Commands:
# - !postreadme <url>: Fetches a GitHub README from the provided URL, parses HTML or Markdown, and posts it in the current Discord channel.
# - !newtool <github_repo_url>: Fetches metadata from the GitHub repository, sends a prompt to OpenAI to generate a tool introduction post, and formats it as a Discord embed.

import discord
from discord.ext import commands
import aiohttp
from openai import AsyncOpenAI
from bs4 import BeautifulSoup
import discrdConfig

# OpenAI client initialization
aclient = AsyncOpenAI(api_key=discrdConfig.OPENAI_APIKEY)

# Setup Discord intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

# Initialize bot
bot = commands.Bot(command_prefix=discrdConfig.COMMAND_PREFIX, intents=intents)

# === Utility Functions ===

async def fncPostReadmeToChannel(channel, readme_url):
    async with aiohttp.ClientSession() as session:
        async with session.get(readme_url) as response:
            if response.status != 200:
                print(f"[GitHub] ❌ Failed to fetch README. Status: {response.status}")
                await channel.send(f"❌ Failed to fetch README file.")
                return

            raw_text = await response.text()
            content_type = response.headers.get('Content-Type', '')

            if "html" in content_type or "<html" in raw_text.lower():
                print("[GitHub] ⚠️ Detected HTML content — cleaning...")
                soup = BeautifulSoup(raw_text, "html.parser")

                for header in soup.find_all("h2"):
                    section_title = header.get_text(strip=True)
                    embed = discord.Embed(title=f"📚 {section_title}", description="", color=discord.Color.blue())
                    next_tag = header.find_next_sibling()

                    while next_tag and next_tag.name in ["p", "ul", "table"]:
                        if next_tag.name == "p":
                            embed.description += next_tag.get_text(strip=True) + "\n\n"
                        elif next_tag.name == "ul":
                            for li in next_tag.find_all("li"):
                                embed.description += f"- {li.get_text(strip=True)}\n"
                            embed.description += "\n"
                        elif next_tag.name == "table":
                            for row in next_tag.find_all("tr"):
                                cols = row.find_all(["td", "th"])
                                if len(cols) >= 2:
                                    link_text = cols[0].get_text(strip=True)
                                    description_text = cols[1].get_text(strip=True)
                                    a_tag = cols[0].find("a")
                                    url = a_tag["href"] if a_tag and a_tag.has_attr("href") else None
                                    field_name = f"🔗 [{link_text}]({url})" if url else f"🔗 {link_text}"
                                    embed.add_field(name=field_name, value=description_text, inline=False)
                        next_tag = next_tag.find_next_sibling()

                    if embed.description.strip() or embed.fields:
                        await channel.send(embed=embed)
                        print(f"[Discord] 📤 Sent embed for: {section_title}")
            else:
                print("[GitHub] 📚 Markdown detected — using raw text fallback.")
                chunks = [raw_text[i:i+1900] for i in range(0, len(raw_text), 1900)]
                for idx, chunk in enumerate(chunks):
                    await channel.send(f"```markdown\n{chunk}\n```")
                    print(f"[Discord] 📤 Posted chunk {idx+1}/{len(chunks)}")

async def fncFetchGitHubRepoInfo(github_url):
    api_url = github_url.replace("https://github.com/", "https://api.github.com/repos/")
    headers = {"Accept": "application/vnd.github.v3+json"}
    async with aiohttp.ClientSession() as session:
        async with session.get(api_url, headers=headers) as response:
            if response.status == 200:
                print(f"[GitHub] ✅ Successfully fetched repo info for {github_url}")
                return await response.json()
            print(f"[GitHub] ❌ Failed to fetch repo info. Status: {response.status}")
            return None

async def fncGenerateToolPost(repo_name, repo_description):
    print(f"[OpenAI] 🛠️ Generating content for {repo_name}...")
    prompt = f"""
You are creating a Discord post to introduce a cybersecurity tool from GitHub.

Use this exact format:

🔧 Tool: [Tool Name]

📖 Description:
[Short paragraph explaining the tool] but don't start with "Tool Name is a cybersecurity tool available on GitHub" make it unique

🔎 Search Tags:
[List of tags separated by spaces like `Cloud` `Web App` `Forensics`] but avoid using the tool name itself. and words like "Penetration Testing", "Cyber Security" 

💬 Quick Hints:
- [hint 1]
- [hint 2]

📋 Notes:
- [note 1]
- [note 2]

Tool Name: {repo_name}
Tool Description: {repo_description}

Write the Discord post now, Keep it Friendly but Informative.
"""
    try:
        response = await aclient.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=600
        )
        print(f"[OpenAI] ✅ Content generated for {repo_name}")
        return response.choices[0].message.content
    except Exception as e:
        print(f"[OpenAI] ❌ OpenAI error: {e}")
        return None

# === Bot Events and Commands ===

@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user.name}")

@bot.command(name="newtool")
async def fncCmdNewTool(ctx, github_url: str):
    print(f"[Command] !newtool triggered by {ctx.author} with URL: {github_url}")
    try:
        await ctx.message.delete()
    except discord.Forbidden:
        print("❌ Missing permissions to delete messages.")
    except discord.HTTPException as e:
        print(f"❌ Failed to delete message: {e}")

    async with ctx.typing():
        repo_info = await fncFetchGitHubRepoInfo(github_url)
        if not repo_info:
            await ctx.send(f"❌ Failed to fetch GitHub information for {github_url}")
            return

        repo_name = repo_info.get("name", "Unknown Tool")
        repo_description = repo_info.get("description", "No description available.")
        repo_link = repo_info.get("html_url", github_url)

        tool_post = await fncGenerateToolPost(repo_name, repo_description)
        if not tool_post:
            await ctx.send("❌ Failed to generate OpenAI content.")
            return

        try:
            description_block = tool_post.split("📖 Description:")[1].split("🔎 Search Tags:")[0].strip()
            tags_block = tool_post.split("🔎 Search Tags:")[1].split("💬 Quick Hints:")[0].strip()
            hints_block = tool_post.split("💬 Quick Hints:")[1].split("📋 Notes:")[0].strip()
            notes_block = tool_post.split("📋 Notes:")[1].strip()
        except Exception as e:
            print(f"[Parse] ❌ Error parsing OpenAI response: {e}")
            await ctx.send("❌ Error parsing OpenAI response.")
            return

        embed = discord.Embed(
            title=f"🔧 {repo_name}",
            url=repo_link,
            description=f"🔗 [View Repository]({repo_link})",
            color=discord.Color.purple()
        )
        embed.add_field(name="📖 Description", value=description_block, inline=False)
        embed.add_field(name="🔎 Search Tags", value=tags_block, inline=False)
        embed.add_field(name="💬 Quick Hints", value=hints_block, inline=False)
        embed.add_field(name="📝 Notes", value=notes_block, inline=False)
        embed.set_footer(text="Post provided by Sasquatch Inc LTD plc ✨")

        await ctx.send(embed=embed)

        status_channel = bot.get_channel(discrdConfig.STATUS_CHANNEL_ID)
        if status_channel:
            try:
                await status_channel.send(f"✅ {ctx.author.mention} posted new tool: **{repo_name}**")
            except Exception as e:
                print(f"[Status] ❌ Error sending status message: {e}")

@bot.command(name="postreadme")
async def fncCmdPostReadme(ctx, url: str):
    await fncPostReadmeToChannel(ctx.channel, url)
    await ctx.send(f"✅ Posted README from {url} into {ctx.channel.mention}")

# === Run the bot ===
bot.run(discrdConfig.DISCORD_APIKEY)
