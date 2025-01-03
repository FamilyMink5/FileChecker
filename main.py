import discord
from discord.ext import commands
import os
import logging
from dotenv import load_dotenv

# 로깅 설정
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s:%(message)s',
    handlers=[
        logging.FileHandler("bot_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# .env 파일 로드
load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

# 봇 초기화

bot = commands.AutoShardedBot(
    command_prefix=commands.when_mentioned_or("!"),
    help_command=None,
    intents=discord.Intents.all(),
    owner_ids=[875214750714314793],
)

# Cogs 로드
async def load_cogs():
    for filename in os.listdir("./cogs"):
        # __init__.py와 utils.py를 제외하고 로드
        if filename.endswith(".py") and filename not in ["__init__.py", "utils.py"]:
            bot.load_extension(f"cogs.{filename[:-3]}")  # 파일 확장자 제거
            logging.info(f"✅ Loaded Cog: {filename}")

@bot.event
async def on_ready():
    logging.info(f"Logged in as {bot.user} (ID: {bot.user.id})")
    
    # # 등록된 명령어 확인
    # logging.info("Registered commands:")
    # for command in bot.tree.get_commands():
    #     logging.info(f"- {command.name}")
    
    # # 전역 슬래시 명령어 동기화
    # try:
    #     synced = await bot.tree.sync()
    #     logging.info(f"Synced {len(synced)} command(s)")
    # except Exception as e:
    #     logging.error(f"Failed to sync commands: {e}")
    
    logging.info("Bot is ready!")

# 봇 실행
async def main():
    async with bot:
        await load_cogs()
        await bot.start(DISCORD_TOKEN)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())