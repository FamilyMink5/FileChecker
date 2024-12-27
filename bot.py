import asyncio
import os
import random
import re
import unicodedata
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import discord
import vt
from discord.ext import commands
from discord import app_commands
from dotenv import load_dotenv

import logging

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

WEBHOOK_URL = os.getenv("WEBHOOK_URL")  # Webhook URL for detailed messages

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

# VT_API_KEYS 동적 로딩
VT_API_KEYS = []
i = 1
while True:
    api_key = os.getenv(f"VT_API_KEY_{i}")
    if api_key:
        VT_API_KEYS.append(api_key)
        i += 1
    else:
        break

if not VT_API_KEYS:
    raise ValueError("No VirusTotal API keys found in environment variables")

ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID"))  # 관리자 유저 ID
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")  # Google Safe Browsing API Key

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# 화이트리스트된 파일 확장자 (해킹에 자주 쓰이는 확장자 포함)
ALLOWED_EXTENSIONS = {
    ".exe", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".js", ".scr", ".bat", ".cmd", ".msi", ".vbs",
    ".jar", ".dll", ".bin", ".apk", ".iso", ".img", ".dmg",
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
    ".txt", ".rtf", ".odt", ".ods", ".odp",
    ".php", ".html", ".htm", ".css", ".py", ".sh", ".rb", ".pl",
    ".c", ".cpp", ".h", ".hpp", ".java", ".class", ".cs", ".vb", ".ps1",
    ".asp", ".aspx", ".jsp", ".cgi", ".swift",
    ".go", ".scala", ".lua", ".m", ".md", ".json", ".xml", ".yaml", ".yml",
    ".sql", ".db", ".dbf", ".bak", ".log", ".cfg", ".conf", ".ini",
    ".sys", ".drv", ".ocx", ".psd", ".tmp", ".xlt", ".xltx", ".mde",
    ".svg", ".ai", ".eps", ".safetensors"
}

REQUEST_LIMIT_PER_MIN = 4
api_usage = {key: {"count": 0, "reset_time": datetime.now()} for key in VT_API_KEYS}
api_key_lock = asyncio.Lock()

# Temp 디렉터리 경로 설정
TEMP_DIR = Path("D:/Temp")
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# Discord 업로드 제한 설정 (바이트 단위)
DISCORD_FILE_SIZE_LIMIT = 8 * 1024 * 1024  # 8MB, 필요에 따라 크기를 조정하세요.

# 설정 저장을 위한 클래스
class BotSettings:
    def __init__(self):
        self.save_temp = True  # Temp 폴더 저장 여부
        self.file_check = True  # 파일 검사 활성화 여부
        self.link_check = True  # 링크 검사 활성화 여부
        self.network_limit = None  # 네트워크 대역폭 제한 (Mbps)

settings = BotSettings()

# 관리자 권한 확인 함수
def is_admin(interaction: discord.Interaction) -> bool:
    return interaction.user.id == ADMIN_USER_ID

def sanitize_filename(filename):
    """
    파일명 내 위험/불가 문자 제거 및 길이 제한, 유니코드 정규화 등
    """
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    sanitized = sanitized.replace(' ', '_')
    sanitized = re.sub(r'_+', '_', sanitized)
    sanitized = sanitized.strip('_')
    sanitized = unicodedata.normalize("NFC", sanitized)
    MAX_NAME_LEN = 50
    if len(sanitized) > MAX_NAME_LEN:
        sanitized = sanitized[:MAX_NAME_LEN]
    logging.debug(f"Sanitized filename: Original='{filename}' Sanitized='{sanitized}'")
    return sanitized

async def get_available_api_key():
    global api_usage
    async with api_key_lock:
        now = datetime.now()
        for api_key, usage in api_usage.items():
            if now >= usage["reset_time"]:
                logging.debug(f"Resetting API key usage count: {api_key[:8]}...")
                usage["count"] = 0
                usage["reset_time"] = now + timedelta(minutes=1)

            if usage["count"] < REQUEST_LIMIT_PER_MIN:
                usage["count"] += 1
                logging.debug(f"Using API key: {api_key[:8]}... Usage count: {usage['count']}")
                return api_key

        sleep_seconds = (min(usage["reset_time"] for usage in api_usage.values()) - now).total_seconds()
        logging.debug(f"All API keys have reached the usage limit. Waiting {sleep_seconds:.1f} seconds before retrying.")
        await asyncio.sleep(sleep_seconds)
        return await get_available_api_key()

def is_allowed_file(filename):
    allowed = any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)
    logging.debug(f"File '{filename}' allowed: {allowed}")
    return allowed

def extract_urls(text):
    """
    메시지 내에서 URL을 추출하는 함수
    """
    logging.debug(f"Extracting URLs from text: {text}")
    url_pattern = re.compile(
        r'(?i)\b((?:https?://|www\d{0,3}[.]|'
        r'[a-z0-9.\-]+[.][a-z]{2,4}/)'
        r'(?:[^\s()<>]+|\((?:[^\s()<>]+|'
        r'(?:\([^\s()<>]+\)))*\))+'
        r'(?:\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))*\)|'
        r'[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
    )
    urls = re.findall(url_pattern, text)
    logging.debug(f"Extracted URLs: {urls}")
    return urls

# 기존 다운로드 함수 수정
async def download_file(url, save_path, max_retries=3, timeout=30):
    if settings.network_limit:
        chunk_size = int((settings.network_limit * 1024 * 1024) / 8)  # Mbps를 bytes/s로 변환
    else:
        chunk_size = 8192  # 기본 청크 크기

    attempt = 0
    while attempt < max_retries:
        try:
            logging.debug(f"Attempting to download file (Attempt {attempt + 1}/{max_retries}): {url}")
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url) as response:
                    logging.debug(f"Received response with status code: {response.status}")
                    
                    if response.status == 200:
                        filename = save_path.name
                        if 'Content-Disposition' in response.headers:
                            cd = response.headers.get('Content-Disposition')
                            fname_match = re.findall('filename="?([^\'";]+)"?', cd)
                            if fname_match:
                                filename = fname_match[0]
                                filename = sanitize_filename(filename)
                        
                        if not settings.save_temp:
                            # 임시 파일 생성
                            temp_file = Path(os.path.join(os.getcwd(), "temp_download"))
                            save_path = temp_file
                        else:
                            guild_name = sanitize_filename(save_path.parent.parent.stem)
                            channel_name = sanitize_filename(save_path.parent.stem)
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
                            temp_dir = TEMP_DIR / guild_name / channel_name / timestamp
                            temp_dir.mkdir(parents=True, exist_ok=True)
                            save_path = temp_dir / filename

                        if not is_allowed_file(filename):
                            logging.debug(f"Downloaded file '{filename}' is not an allowed type.")
                            return None

                        # 청크 단위로 파일 다운로드
                        with save_path.open('wb') as f:
                            async for chunk in response.content.iter_chunked(chunk_size):
                                f.write(chunk)
                                if settings.network_limit:  # None이면 대역폭 제한 없음
                                    await asyncio.sleep(len(chunk) / (chunk_size))

                        logging.debug(f"File downloaded successfully: {save_path}")
                        return save_path
                    else:
                        logging.error(f"Failed to download file: Status code {response.status}")
                        return None

        except Exception as e:
            logging.exception(f"Error downloading file: {e}")
            attempt += 1
            if attempt < max_retries:
                await asyncio.sleep(2)

    logging.error(f"Failed to download file after {max_retries} attempts: {url}")
    return None

async def process_url(url, message):
    """
    URL을 처리하는 함수:
    1. GET 요청을 보내 응답 상태를 확인
    2. 파일 다운로드 후 확장자 확인 및 검사
    """
    try:
        # GET 요청 보내기
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                logging.debug(f"GET request to {url} returned status {response.status}")
                if response.status != 200:
                    await message.channel.send(f"링크 `{url}`은 비정상적인 응답을 반환했습니다. (상태 코드: {response.status})")
                    return

        # 파일 다운로드 및 검사
        parsed_url = urlparse(url)
        file_name = Path(parsed_url.path).name
        if not file_name:
            logging.debug(f"URL `{url}`에서 파일 이름을 추출할 수 없습니다.")
            await message.channel.send(f"링크 `{url}`에서 파일 이름을 추출할 수 없습니다.")
            return

        sanitized_file_name = sanitize_filename(file_name)

        # 파일 저장 경로 생성
        guild_name = sanitize_filename(message.guild.name if message.guild else "DM")
        channel_name = sanitize_filename(message.channel.name if isinstance(message.channel, discord.TextChannel) else "DM")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # ms 포함된 시간
        save_path = TEMP_DIR / guild_name / channel_name / timestamp
        save_path.mkdir(parents=True, exist_ok=True)

        temp_file_path = save_path / sanitized_file_name

        downloaded_file = await download_file(url, temp_file_path)
        if not downloaded_file:
            await message.channel.send(f"링크 `{url}`에서 파일을 다운로드할 수 없습니다.")
            return

        # 파일 확장자 확인
        if not is_allowed_file(downloaded_file.name):
            logging.debug(f"링크 `{url}`에서 다운로드한 파일 `{downloaded_file.name}`은 지원되지 않는 확장자입니다.")
            await message.channel.send(f"링크 `{url}`에서 다운로드한 파일 `{downloaded_file.name}`은 지원되지 않는 확장자입니다.")
            return

        # 파일 크기 확인
        file_size = downloaded_file.stat().st_size

        # 메시지 삭제
        await message.delete()
        logging.debug(f"메시지가 삭제되었습니다: {message.id}")

        # VirusTotal 스캔 수행
        api_key = await get_available_api_key()
        async with vt.Client(api_key) as client:
            embed = discord.Embed(
                title="파일 검사 진행 중",
                description=f"링크에서 다운로드한 파일 `{downloaded_file.name}` 검사 준비 중입니다...\n보낸 유저: {message.author.mention}\n파일 사이즈: {file_size / (1024 * 1024):.2f}MB",
                color=discord.Color.blue()
            )
            status_message = await message.channel.send(content=message.author.mention, embed=embed)
            analysis = await scan_file_with_vt(client, downloaded_file, embed, status_message, message, file_size)

            # 검사 결과 처리
            if analysis.status == "completed":
                stats = analysis.stats
                await handle_scan_results(message, downloaded_file.name, file_size, stats, status_message, downloaded_file)
            else:
                await message.channel.send(f"링크에서 다운로드한 파일 `{downloaded_file.name}`의 검사 시간이 초과되었습니다.")

    except Exception as e:
        logging.exception(f"URL `{url}` 처리 중 오류 발생: {e}")
        await message.channel.send(f"링크 `{url}` 처리 중 오류가 발생했습니다: {str(e)}")

async def scan_file_with_vt(client, file_path, embed, status_message, message, file_size):
    """
    VirusTotal API를 사용하여 파일을 스캔하는 함수 (파일 객체를 직접 전송)
    """
    logging.debug(f"Starting VirusTotal file scan: {file_path}")
    try:
        # 진행 상황 업데이트: 스캔 요청 중
        embed.description = f"파일 `{file_path.name}` 스캔을 요청 중입니다...\n보낸 유저: {message.author.mention}\n파일 사이즈: {file_size / (1024 * 1024):.2f}MB"
        await status_message.edit(embed=embed)
        logging.debug(f"Updated status message for scanning: {status_message.id}")

        # 파일 객체를 직접 사용하여 스캔
        with file_path.open('rb') as f:
            logging.debug(f"Sending file to VirusTotal for scanning: {file_path}")
            analysis = await client.scan_file_async(f)
        logging.debug(f"Scan request completed: Analysis ID: {analysis.id}")

        # 진행 상황 업데이트: 스캔 진행 중
        embed.description = f"파일 `{file_path.name}` 스캔을 진행 중입니다...\n보낸 유저: {message.author.mention}\n파일 사이즈: {file_size / (1024 * 1024):.2f}MB"
        await status_message.edit(embed=embed)
        logging.debug(f"Updated status message: Scanning in progress.")

        # 스캔 결과 확인 (최대 시도 횟수: 30)
        max_attempts = 30
        attempt = 0

        while attempt < max_attempts:
            try:
                logging.debug(f"Checking analysis status: Attempt {attempt + 1}/{max_attempts}")
                analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                logging.debug(f"Analysis status: {analysis.status}")

                if analysis.status == "completed":
                    logging.debug("Analysis completed successfully.")
                    break

                attempt += 1
                logging.debug(f"Analysis not completed yet. Retrying in 10 seconds...")
                await asyncio.sleep(10)

            except Exception as e:
                logging.exception(f"Error checking analysis status: {e}")
                attempt += 1
                await asyncio.sleep(5)

        if attempt >= max_attempts:
            # 분석 시간이 초과된 경우
            logging.warning(f"Analysis timed out for file: {file_path}")
            embed.description = f"⏰ 파일 `{file_path.name}`의 분석 시간이 초과되었습니다.\n보낸 유저: {message.author.mention}\n파일 사이즈: {file_size / (1024 * 1024):.2f}MB"
            await status_message.edit(embed=embed)
            raise TimeoutError("Analysis timed out.")

        logging.debug(f"Returning analysis result: {analysis.id}")
        return analysis

    except Exception as e:
        logging.exception(f"Detailed error during VT scan: {e}")
        raise

async def check_url_safety(url):
    """
    Google Safe Browsing API를 사용하여 URL의 안전성을 검사합니다.
    """
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "client": {
            "clientId": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/131.0.0.0 Safari/537.36",
            "clientVersion": "131.0.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=payload, headers=headers, params={"key": SAFE_BROWSING_API_KEY}) as response:
                response_text = await response.text()
                logging.debug(f"Google Safe Browsing API response status: {response.status}")
                logging.debug(f"Google Safe Browsing API response body: {response_text}")

                if response.status != 200:
                    logging.error(f"Google Safe Browsing API request failed with status {response.status}")
                    return "unknown"

                data = await response.json()
                if "matches" in data:
                    logging.debug(f"URL detected as malicious: {url}")
                    return "malicious"
                else:
                    logging.debug(f"URL is safe: {url}")
                    return "safe"
    except Exception as e:
        logging.exception(f"Error during Google Safe Browsing API request: {e}")
        return "unknown"

async def send_detailed_message_via_webhook(message, filename, file_size, stats):
    """
    Webhook을 통해 자세한 메시지를 전송합니다.
    """
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    harmless_count = stats.get("harmless", 0)
    undetected_count = stats.get("undetected", 0)
    timeout_count = stats.get("timeout", 0)
    confirmed_timeout_count = stats.get("confirmed-timeout", 0)
    failure_count = stats.get("failure", 0)
    type_unsurported_count = stats.get("type-unsupported", 0)
    total_count = sum(stats.values())

    embed = discord.Embed(
        title="파일 검사 로그",
        color=discord.Color.red() if malicious_count + suspicious_count > 0 else discord.Color.green()
    )

    embed.add_field(name="파일 이름", value=filename, inline=False)
    embed.add_field(name="파일 사이즈", value=f"{file_size / (1024 * 1024):.2f}MB", inline=False)
    embed.add_field(name="보낸 유저", value=message.author.mention, inline=False)
    embed.add_field(name="총 검사 엔진 수", value=str(total_count), inline=False)
    embed.add_field(name="✅ 안전 판정 엔진 수", value=str(undetected_count + harmless_count), inline=False)
    embed.add_field(name="‼️ 유해 판정 엔진 수", value=str(malicious_count), inline=False)
    embed.add_field(name="⚠️ 의심 판정 엔진 수", value=str(suspicious_count), inline=False)
    embed.add_field(name="⏰ 타임아웃 엔진 수", value=str(timeout_count + confirmed_timeout_count), inline=False)
    embed.add_field(name="❔ 판정 실패 엔진 수", value=str(failure_count), inline=False)
    embed.add_field(name="❌ 형식 미지원 엔진 수", value=str(type_unsurported_count), inline=False)

    if not WEBHOOK_URL:
        logging.error("WEBHOOK_URL is not set in the environment variables.")
        return

    # Webhook에 보낼 페이로드 준비
    payload = {
        "embeds": [embed.to_dict()],
        "username": "FileChecker",  # 선택 사항: Webhook의 사용자명 설정
        "avatar_url": "https://www.familymink5.kr/assets/img/serverinfo.webp"  # 선택 사항: Webhook의 아바타 설정
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(WEBHOOK_URL, json=payload) as resp:
                if resp.status == 204:
                    logging.debug("Detailed message sent via webhook.")
                else:
                    response_text = await resp.text()
                    logging.error(f"Failed to send webhook message: {resp.status} {response_text}")
        except Exception as e:
            logging.exception(f"Error sending message via webhook: {e}")

async def handle_scan_results(message, filename, file_size, stats, status_message, file_path):
    """
    파일 검사 결과를 처리하고 사용자에게 응답을 전송하는 함수
    """
    # 분석 결과에서 stats 추출
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    harmless_count = stats.get("harmless", 0)
    undetected_count = stats.get("undetected", 0)
    timeout_count = stats.get("timeout", 0)
    confirmed_timeout_count = stats.get("confirmed-timeout", 0)
    failure_count = stats.get("failure", 0)
    type_unsurported_count = stats.get("type-unsupported", 0)
    total_count = sum(stats.values())

    # 결과 임베드 생성
    result_embed = discord.Embed(
        title="파일 검사 결과",
        color=discord.Color.red() if malicious_count + suspicious_count > 0 else discord.Color.green()
    )
    result_embed.add_field(name="파일 이름", value=filename, inline=False)
    result_embed.add_field(name="파일 사이즈", value=f"{file_size / (1024 * 1024):.2f}MB", inline=False)
    result_embed.add_field(name="보낸 유저", value=message.author.mention, inline=False)
    result_embed.add_field(name="총 검사 엔진 수", value=str(total_count), inline=False)
    result_embed.add_field(name="✅ 안전 판정 엔진 수", value=str(undetected_count + harmless_count), inline=False)
    result_embed.add_field(name="‼️ 유해 판정 엔진 수", value=str(malicious_count), inline=False)

    try:
        if malicious_count + suspicious_count > 0:
            result_embed.description = f"⚠️ 이 파일은 잠재적으로 위험할 수 있습니다!"
            # 관리자 맨션
            admin_user = await bot.fetch_user(ADMIN_USER_ID)
            content = f"{message.author.mention} {admin_user.mention}"
            await send_detailed_message_via_webhook(message, filename, file_size, stats)
            await status_message.reply(content=content, embed=result_embed)
            logging.debug("Scan result sent with admin mention.")
        else:
            result_embed.description = f"✅ 이 파일은 안전한 것으로 보입니다."
            await send_detailed_message_via_webhook(message, filename, file_size, stats)
            await status_message.reply(content=message.author.mention, embed=result_embed)

            # 파일 크기가 Discord 업로드 제한을 초과하는지 확인
            if file_size > DISCORD_FILE_SIZE_LIMIT:
                logging.warning(f"File is too large to send: {file_size} bytes")
                # 사용자에게 파일이 너무 커서 전송할 수 없음을 알리는 메시지 전송
                await message.channel.send(
                    f"⚠️ 파일 `{filename}`은 안전하지만 크기가 {file_size / (1024 * 1024):.2f}MB로 Discord 업로드 제한을 초과하여 전송할 수 없습니다."
                )
            else:
                # 안전한 파일이면 Discord 파일로 별도 전송
                discord_file = discord.File(fp=file_path)
                await message.channel.send(file=discord_file)
                logging.debug("Safe file sent as a separate message.")

    except Exception as e:
        logging.exception(f"Error while handling scan results: {e}")
        await message.channel.send(f"파일 `{filename}` 처리 중 오류가 발생했습니다: {str(e)}")

async def toggle_feature(interaction: discord.Interaction, feature: app_commands.Choice[str]):
    if not is_admin(interaction):
        await interaction.response.send_message("이 명령어는 관리자만 사용할 수 있습니다.", ephemeral=True)
        return

    feature_name = feature.value
    current_value = getattr(settings, feature_name)
    new_value = not current_value
    setattr(settings, feature_name, new_value)

    # save_temp가 꺼지면 Temp 폴더 초기화
    if feature_name == "save_temp" and not new_value:
        try:
            for item in TEMP_DIR.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            logging.info("Temp folder cleared after disabling save_temp")
        except Exception as e:
            logging.error(f"Error clearing temp folder: {e}")

    status = "활성화" if new_value else "비활성화"
    feature_names = {
        "save_temp": "임시 파일 저장",
        "file_check": "파일 검사",
        "link_check": "링크 검사"
    }
    
    await interaction.response.send_message(
        f"✅ {feature_names[feature_name]}이(가) {status}되었습니다.", 
        ephemeral=True
    )
    logging.info(f"Feature {feature_name} toggled to {new_value}")

# 슬래시 커맨드 그룹 생성
@bot.tree.command(name="clear", description="Temp 폴더를 초기화합니다")
async def clear_temp(interaction: discord.Interaction):
    if not is_admin(interaction):
        await interaction.response.send_message("이 명령어는 관리자만 사용할 수 있습니다.", ephemeral=True)
        return

    try:
        # Temp 폴더 내용 삭제
        for item in TEMP_DIR.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
        
        await interaction.response.send_message("✅ Temp 폴더가 초기화되었습니다.", ephemeral=True)
        logging.info("Temp folder cleared successfully")
    except Exception as e:
        await interaction.response.send_message(f"❌ Temp 폴더 초기화 중 오류가 발생했습니다: {str(e)}", ephemeral=True)
        logging.error(f"Error clearing temp folder: {e}")

@bot.tree.command(name="set", description="봇 설정을 변경합니다")
@app_commands.describe(network="네트워크 대역폭 제한 (Mbps). 0은 무제한")
async def set_network(interaction: discord.Interaction, network: int):
    if not is_admin(interaction):
        await interaction.response.send_message("이 명령어는 관리자만 사용할 수 있습니다.", ephemeral=True)
        return

    if network < 0:
        await interaction.response.send_message("❌ 네트워크 대역폭은 0 이상이어야 합니다.", ephemeral=True)
        return

    settings.network_limit = None if network == 0 else network
    status_msg = "무제한" if network == 0 else f"{network}Mbps"
    
    await interaction.response.send_message(
        f"✅ 네트워크 대역폭이 {status_msg}으로 설정되었습니다.", 
        ephemeral=True
    )
    logging.info(f"Network bandwidth limit set to {status_msg}")

@bot.tree.command(name="toggle", description="봇의 기능을 켜거나 끕니다")
@app_commands.describe(feature="토글할 기능 선택")
@app_commands.choices(feature=[
    app_commands.Choice(name="save_temp", value="save_temp"),
    app_commands.Choice(name="file_check", value="file_check"),
    app_commands.Choice(name="link_check", value="link_check")
])

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # 메시지에서 링크를 추출
    urls = extract_urls(message.content)

     # 링크 검사가 활성화된 경우에만 수행
    if settings.link_check:
        urls = extract_urls(message.content)
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
        if message.attachments:
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

                pass

    await bot.process_commands(message)

@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        logging.info(f"Synced {len(synced)} command(s)")
    except Exception as e:
        logging.error(f"Failed to sync commands: {e}")
    logging.info(f"Logged in as {bot.user}!")

bot.run(DISCORD_TOKEN)