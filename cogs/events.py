from discord.ext import commands
from cogs.utils import settings, extract_urls, process_url, is_allowed_file, TEMP_DIR, sanitize_filename, get_available_api_key, scan_file_with_vt, handle_scan_results, check_url_safety
from datetime import datetime
import discord
import vt

from main import logging, bot

class EventCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author.bot:
            return

        # 메시지에서 링크를 추출
        urls = extract_urls(message.content)

        # 링크 검사가 활성화된 경우에만 수행
        if settings.link_check:
            if urls:
                for url in urls:
                    safety = await check_url_safety(url)
                    if safety == "malicious":
                        await message.add_reaction("❗️")
                        await message.delete()
                        await message.channel.send(f"링크 `{url}`은 안전하지 않으므로 삭제되었습니다.")
                    elif safety == "safe":
                        await message.add_reaction("✅")
                        await process_url(url, message)
                    else:
                        await message.add_reaction("❓")

        if settings.file_check and message.attachments:
            # 첨부 파일 처리
            for attachment in message.attachments:
                filename = attachment.filename
                if is_allowed_file(filename):
                    logging.info(f"Received file for scanning: {filename}")
                    
                    # 새로운 저장 경로 생성
                    guild_name = sanitize_filename(message.guild.name if message.guild else "DM")
                    channel_name = sanitize_filename(message.channel.name if isinstance(message.channel, discord.TextChannel) else "DM")
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
                    temp_dir = TEMP_DIR / guild_name / channel_name / timestamp
                    temp_dir.mkdir(parents=True, exist_ok=True)
                    
                    temp_path = temp_dir / filename

                    try:
                        logging.debug(f"Saving attachment: {attachment.url}")
                        await attachment.save(temp_path)
                        
                        if not temp_path.exists():
                            error_msg = f"File was not saved: {temp_path}"
                            logging.error(error_msg)
                            raise FileNotFoundError(error_msg)

                        file_size = temp_path.stat().st_size
                        logging.debug(f"File size: {file_size} bytes")

                        await message.delete()
                        logging.debug(f"Deleted user message: {message.id}")

                        embed = discord.Embed(
                            title="파일 검사 진행 중",
                            description=f"파일 `{filename}` 검사 준비 중입니다...\n보낸 유저: {message.author}\n파일 사이즈: {file_size / (1024 * 1024):.2f}MB",
                            color=discord.Color.blue()
                        )
                        status_message = await message.channel.send(content=message.author.mention, embed=embed)

                        api_key = await get_available_api_key()
                        async with vt.Client(api_key) as client:
                            analysis = await scan_file_with_vt(client, temp_path, embed, status_message, message, file_size)

                            if analysis.status != "completed":
                                timeout_embed = discord.Embed(
                                    title="파일 검사 시간 초과",
                                    description=f"⏰ 파일 `{filename}`의 검사 시간이 초과되었습니다.",
                                    color=discord.Color.orange()
                                )
                                await message.channel.send(content=message.author.mention, embed=timeout_embed)
                                return

                            stats = analysis.stats
                            await handle_scan_results(message, filename, file_size, stats, status_message, temp_path)

                    except TimeoutError:
                        logging.warning(f"Analysis timed out for file: {filename}")
                    except Exception as e:
                        error_msg = f"파일 `{filename}` 검사 중 오류가 발생했습니다: {str(e)}"
                        logging.exception(f"Exception occurred: {str(e)}")
                        await message.channel.send(error_msg)

                else:
                    logging.debug(f"Unsupported file type received: {filename}")
                    await message.channel.send(f"파일 `{filename}`은(는) 지원되지 않는 파일 형식입니다.")

        # 명령어 처리
        # bot.user가 None인지 확인
        if bot.user is not None:
            await bot.process_commands(message)  # bot.user가 None이 아닐 때만 호출

async def setup(bot):
    await bot.add_cog(EventCog(bot))
