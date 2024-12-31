import json
import os
import re
import unicodedata
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
from dotenv import load_dotenv
from pathlib import Path
import aiohttp
import asyncio
import discord
import vt
from main import logging, bot

# .env 파일 로드
load_dotenv()

WEBHOOK_URL = os.getenv("WEBHOOK_URL")  # Webhook URL for detailed messages
ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID"))  # 관리자 유저 ID
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")  # Google Safe Browsing API Key

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

# 서버별 설정을 저장하는 전역 변수
SETTINGS_FILE = "server_settings.json"

# Discord 업로드 제한 설정 (바이트 단위)
DISCORD_FILE_SIZE_LIMIT = 8 * 1024 * 1024  # 8MB, 필요에 따라 크기를 조정하세요.

# 화이트리스트된 파일 확장자 (해킹에 자주 쓰이는 확장자 포함)
ALLOWED_EXTENSIONS = {
    ".exe", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".js", ".scr", ".bat", ".cmd", ".msi", ".vbs",
    ".jar", ".dll", ".bin", ".apk", ".iso", ".img", ".dmg",
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
    ".txt", ".rtf", ".odt", ".ods", ".odp", ".csv", ".json",
    ".php", ".html", ".htm", ".css", ".py", ".sh", ".rb", ".pl",
    ".c", ".cpp", ".h", ".hpp", ".java", ".class", ".cs", ".vb", ".ps1",
    ".asp", ".aspx", ".jsp", ".cgi", ".swift", ".kt", ".ts"
    ".go", ".scala", ".lua", ".m", ".md", ".json", ".xml", ".yaml", ".yml",
    ".sql", ".db", ".dbf", ".bak", ".log", ".cfg", ".conf", ".ini",
    ".sys", ".drv", ".ocx", ".psd", ".tmp", ".xlt", ".xltx", ".mde",
    ".svg", ".ai", ".eps", ".safetensors", ".mov", ".mp4", ".avi", ".mkv",
    ".mp3", ".wav", ".flac", ".ogg", ".wma", ".aac", ".m4a", ".flv",
}

REQUEST_LIMIT_PER_MIN = 4
api_usage = {key: {"count": 0, "reset_time": datetime.now()} for key in VT_API_KEYS}
api_key_lock = asyncio.Lock()

# Temp 디렉터리 경로 설정
TEMP_DIR = Path("D:/Temp")
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# 설정 저장을 위한 클래스
class BotSettings:
    def __init__(self, save_temp=True, file_check=True, link_check=True, network_limit=None):
        self.save_temp = save_temp  # Temp 폴더 저장 여부
        self.file_check = file_check  # 파일 검사 활성화 여부
        self.link_check = link_check  # 링크 검사 활성화 여부
        self.network_limit = network_limit  # 네트워크 대역폭 제한 (Mbps)

    def __repr__(self):
        return f"BotSettings(save_temp={self.save_temp}, file_check={self.file_check}, link_check={self.link_check}, network_limit={self.network_limit})"

settings = BotSettings()

async def create_error_embed(title, description, url=None, status_code=None):
    """
    Creates a standardized error embed for the bot
    """
    error_embed = discord.Embed(
        title=title,
        description=description,
        color=discord.Color.red()
    )
    if url:
        error_embed.add_field(name="링크", value=url, inline=False)
    if status_code:
        error_embed.add_field(name="상태 코드", value=status_code, inline=False)
    return error_embed

async def send_error_message(message, embed, admin_mention=True):
    """
    Sends an error message with optional admin mention
    """
    try:
        if admin_mention:
            try:
                admin_user = await bot.fetch_user(ADMIN_USER_ID)
                content = f"{message.author.mention} {admin_user.mention}"
            except:
                content = f"{message.author.mention} (Admin user could not be fetched)"
        else:
            content = message.author.mention
            
        await message.reply(content=content, embed=embed)
        logging.debug("Error message sent successfully")
    except Exception as e:
        logging.error(f"Failed to send error message: {e}")

# 관리자 권한 확인 함수
def is_admin(interaction: discord.Interaction) -> bool:
    return interaction.user.id == ADMIN_USER_ID

def load_server_settings():
    """
    JSON 파일에서 서버별 설정을 로드합니다.
    """
    global server_settings
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                # JSON 파일 읽기
                data = json.load(f)
                # 서버별 설정 복원
                server_settings = {
                    int(guild_id): BotSettings(**settings)  # 딕셔너리를 객체로 변환
                    for guild_id, settings in data.items()
                }
            logging.info("✅ Server settings loaded from file.")
        else:
            logging.info("⚠️ No settings file found. Using default settings.")
    except Exception as e:
        logging.error(f"❌ Failed to load server settings: {e}")
        server_settings = {}

def save_server_settings():
    """
    서버별 설정을 JSON 파일로 저장합니다.
    """
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            # 서버별 설정을 딕셔너리로 변환
            data = {    
                str(guild_id): vars(settings)  # 객체를 딕셔너리로 변환
                for guild_id, settings in server_settings.items()
            }
            json.dump(data, f, ensure_ascii=False, indent=4)
        logging.info("✅ Server settings saved to file.")
    except Exception as e:
        logging.error(f"❌ Failed to save server settings: {e}")

# 서버별 설정을 로드하거나 기본값 생성
def get_server_settings(guild_id):
    global server_settings
    if guild_id not in server_settings:
        server_settings[guild_id] = BotSettings()  # 새로 생성
    return server_settings[guild_id]

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

async def create_download_error_embed(title, description, url=None, filename=None, error=None, size=None):
    """
    Creates a standardized download error embed
    """
    error_embed = discord.Embed(
        title=title,
        description=description,
        color=discord.Color.red()
    )
    if url:
        error_embed.add_field(name="다운로드 URL", value=url, inline=False)
    if filename:
        error_embed.add_field(name="파일명", value=filename, inline=False)
    if size:
        error_embed.add_field(name="파일 크기", value=f"{size / (1024*1024):.2f}MB", inline=False)
    if error:
        error_embed.add_field(name="오류 내용", value=str(error), inline=False)
    return error_embed

async def download_file(url, save_path, message, max_retries=3, base_timeout=30):
    """
    Downloads a file with improved error handling and progress tracking
    
    Args:
        url (str): URL to download from
        save_path (Path): Path to save the file to
        message (discord.Message): Original message for error reporting
        max_retries (int): Maximum number of retry attempts
        base_timeout (int): Base timeout in seconds
        
    Returns:
        Path: Path to the downloaded file or None if download failed
    """
    if settings.network_limit:
        chunk_size = int((settings.network_limit * 1024 * 1024) / 8)
    else:
        chunk_size = 8192

    attempt = 0
    filename = save_path.name
    
    while attempt < max_retries:
        try:
            current_timeout = base_timeout * (attempt + 1)
            logging.debug(f"Attempting download (Attempt {attempt + 1}/{max_retries}): {url}")
            
            timeout = aiohttp.ClientTimeout(
                total=current_timeout * 2,
                connect=current_timeout,
                sock_read=current_timeout
            )

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        error_embed = await create_download_error_embed(
                            title="다운로드 실패",
                            description=f"❌ HTTP 상태 코드 {response.status}로 다운로드에 실패했습니다.",
                            url=url,
                            filename=filename
                        )
                        await send_error_message(message, error_embed)
                        attempt += 1
                        if attempt < max_retries:
                            await asyncio.sleep(2 ** attempt)
                        continue

                    total_size = int(response.headers.get('content-length', 0))
                    if total_size > DISCORD_FILE_SIZE_LIMIT:
                        error_embed = await create_download_error_embed(
                            title="파일 크기 초과",
                            description="❌ 파일이 Discord 업로드 제한(8MB)을 초과합니다.",
                            url=url,
                            filename=filename,
                            size=total_size
                        )
                        await send_error_message(message, error_embed)
                        return None

                    if 'Content-Disposition' in response.headers:
                        cd = response.headers.get('Content-Disposition')
                        fname_match = re.findall('filename="?([^\'";]+)"?', cd)
                        if fname_match:
                            filename = sanitize_filename(fname_match[0])
                    
                    # 저장 경로 설정
                    if not settings.save_temp:
                        save_path = Path(os.path.join(os.getcwd(), "temp_download"))
                    else:
                        guild_name = sanitize_filename(save_path.parent.parent.stem)
                        channel_name = sanitize_filename(save_path.parent.stem)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
                        temp_dir = TEMP_DIR / guild_name / channel_name / timestamp
                        temp_dir.mkdir(parents=True, exist_ok=True)
                        save_path = temp_dir / filename

                    if not is_allowed_file(filename):
                        error_embed = await create_download_error_embed(
                            title="지원하지 않는 파일 형식",
                            description="❌ 이 파일 형식은 지원되지 않습니다.",
                            url=url,
                            filename=filename
                        )
                        await send_error_message(message, error_embed)
                        return None

                    # 다운로드 진행
                    downloaded_size = 0
                    last_progress_log = 0
                    
                    with save_path.open('wb') as f:
                        async for chunk in response.content.iter_chunked(chunk_size):
                            try:
                                f.write(chunk)
                                downloaded_size += len(chunk)

                                if total_size > 0:
                                    progress = (downloaded_size / total_size) * 100
                                    if progress - last_progress_log >= 10:
                                        logging.debug(f"Download progress: {progress:.1f}%")
                                        last_progress_log = progress

                                if settings.network_limit:
                                    await asyncio.sleep(len(chunk) / (chunk_size))

                            except asyncio.TimeoutError:
                                error_embed = await create_download_error_embed(
                                    title="다운로드 시간 초과",
                                    description=f"⏰ 청크 다운로드 중 시간 초과 ({current_timeout}초)",
                                    url=url,
                                    filename=filename,
                                    size=downloaded_size
                                )
                                await send_error_message(message, error_embed)
                                raise

                    logging.debug(f"Download completed: {save_path}")
                    return save_path

        except asyncio.TimeoutError as e:
            error_embed = await create_download_error_embed(
                title="다운로드 시간 초과",
                description=f"⏰ 다운로드 시도 {attempt + 1} 실패",
                url=url,
                filename=filename,
                error=str(e)
            )
            await send_error_message(message, error_embed)
            attempt += 1

        except aiohttp.ClientError as e:
            error_embed = await create_download_error_embed(
                title="네트워크 오류",
                description=f"🌐 다운로드 시도 {attempt + 1} 실패",
                url=url,
                filename=filename,
                error=str(e)
            )
            await send_error_message(message, error_embed)
            attempt += 1

        except Exception as e:
            error_embed = await create_download_error_embed(
                title="예기치 않은 오류",
                description="❌ 파일 다운로드 중 오류가 발생했습니다.",
                url=url,
                filename=filename,
                error=str(e)
            )
            await send_error_message(message, error_embed)
            logging.exception(f"Unexpected error during download: {e}")
            return None

        if attempt < max_retries:
            await asyncio.sleep(2 ** attempt)
        
    error_embed = await create_download_error_embed(
        title="다운로드 실패",
        description=f"❌ {max_retries}회 시도 후 다운로드에 실패했습니다.",
        url=url,
        filename=filename
    )
    await send_error_message(message, error_embed)
    return None

def ensure_url_has_scheme(url):
    """
    URL에 스킴이 없으면 기본값으로 'https://'를 추가합니다.
    잘못된 URL 형식을 수정합니다.
    """
    parsed_url = urlparse(url)

    # 스킴이 없으면 기본값으로 'https://' 추가
    if not parsed_url.scheme:
        # netloc이 비어 있는 경우 path에 도메인이 포함되었을 가능성 처리
        if not parsed_url.netloc:
            # path가 도메인과 경로를 포함한 경우 처리
            parts = parsed_url.path.split('/', 1)
            netloc = parts[0]  # 첫 번째 부분을 netloc으로 간주
            path = f"/{parts[1]}" if len(parts) > 1 else ""  # 나머지는 path로 간주
        else:
            netloc = parsed_url.netloc
            path = parsed_url.path

        # 올바른 URL 조합
        url = urlunparse(('https', netloc, path, parsed_url.params, parsed_url.query, parsed_url.fragment))
    return url

async def process_url(self, url, message):
    """
    URL을 처리하는 함수
    """
    try:
        url = ensure_url_has_scheme(url)
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                logging.debug(f"GET 요청 결과 - URL: {url}, 상태 코드: {response.status}")
                if response.status != 200:
                    error_embed = await create_error_embed(
                        title="GET 요청 실패 오류",
                        description="❗ GET 요청에 실패했습니다.\n해당 링크가 유효한지 확인하십시오.",
                        url=url,
                        status_code=response.status
                    )
                    await send_error_message(message, error_embed)
                    return

        parsed_url = urlparse(url)
        file_name = Path(parsed_url.path).name
        if not file_name:
            error_embed = await create_error_embed(
                title="링크 추출 오류",
                description="❗ 링크 추출에 실패했습니다.\n해당 메시지에 링크가 있는지 확인하십시오.",
                url=url
            )
            error_embed.add_field(name="추출된 링크", value=parsed_url, inline=False)
            await send_error_message(message, error_embed)
            return

        # 파일 이름 정리
        sanitized_file_name = sanitize_filename(file_name)

        # 파일 저장 경로 생성
        guild_name = sanitize_filename(message.guild.name if message.guild else "DM")
        channel_name = sanitize_filename(message.channel.name if isinstance(message.channel, discord.TextChannel) else "DM")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        save_path = TEMP_DIR / guild_name / channel_name / timestamp
        save_path.mkdir(parents=True, exist_ok=True)

        temp_file_path = save_path / sanitized_file_name

        # 파일 다운로드
        downloaded_file = await download_file(url, temp_file_path, message)
        if not downloaded_file:
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
                await handle_link_scan_results(self, message, downloaded_file.name, file_size, stats, status_message, url)
            else:
                error_embed = await create_error_embed(
                    title="검사 시간 초과",
                    description=f"⏰ 파일 `{downloaded_file.name}`의 검사 시간이 초과되었습니다.",
                )
                await send_error_message(message, error_embed)

    except Exception as e:
        error_embed = await create_error_embed(
            title="URL 처리 오류",
            description=f"❗ 링크 처리 중 오류가 발생했습니다: {str(e)}",
            url=url
        )
        await send_error_message(message, error_embed)
        logging.exception(f"URL `{url}` 처리 중 오류 발생: {e}")

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
            error_embed = await create_error_embed(
                title="스캔 시간 초과",
                description=f"⏰ 파일 `{file_path.name}`의 분석 시간이 초과되었습니다.",
            )
            error_embed.add_field(name="파일 크기", value=f"{file_size / (1024 * 1024):.2f}MB", inline=False)
            error_embed.add_field(name="보낸 유저", value=message.author.mention, inline=False)
            await send_error_message(message, error_embed, admin_mention=True)
            raise TimeoutError("Analysis timed out.")

        return analysis

    except Exception as e:
        error_embed = await create_error_embed(
            title="스캔 오류",
            description=f"❗ 파일 스캔 중 오류가 발생했습니다: {str(e)}",
        )
        await send_error_message(message, error_embed, admin_mention=True)
        logging.exception(f"Detailed error during VT scan: {e}")
        raise

async def check_url_with_virustotal(url):
    """
    VirusTotal API를 사용하여 URL의 안전성을 검사합니다.
    """
    try:
        api_key = await get_available_api_key()
        async with vt.Client(api_key) as client:
            analysis = await client.scan_url_async(url)
            logging.debug(f"VirusTotal analysis ID: {analysis.id}")

            # 결과를 확인 (최대 시도 횟수: 30)
            max_attempts = 30
            attempt = 0
            while attempt < max_attempts:
                analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                if analysis.status == "completed":
                    return analysis.stats  # 통계 데이터 반환
                attempt += 1
                await asyncio.sleep(10)  # 10초 대기

            raise TimeoutError("VirusTotal URL analysis timed out.")

    except Exception as e:
        logging.exception(f"VirusTotal URL 검사 오류: {e}")
        return None


async def check_url_safety(url):
    """
    Google Safe Browsing 및 VirusTotal API를 사용하여 URL의 안전성을 검사합니다.
    """
    # Google Safe Browsing 검사
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {"clientId": "your_client_id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=payload, headers=headers, params={"key": SAFE_BROWSING_API_KEY}) as response:
                if response.status == 200:
                    data = await response.json()
                    if "matches" in data:
                        logging.debug(f"Google Safe Browsing: URL `{url}` is malicious.")
                        return "malicious"
    except Exception as e:
        logging.exception(f"Google Safe Browsing 검사 오류: {e}")

    # VirusTotal 검사
    vt_stats = await check_url_with_virustotal(url)
    if vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            logging.debug(f"VirusTotal: URL `{url}` is malicious or suspicious.")
            return "malicious"

    return "safe"

async def send_detailed_message_via_webhook(self, message, filename, file_size, stats):
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
    content = ""
    if malicious_count + suspicious_count > 0:
        embed.description = f"⚠️ 이 파일은 잠재적으로 위험할 수 있습니다!"
        # 관리자 맨션
        try:
            admin_user = await self.bot.fetch_user(ADMIN_USER_ID)
        except AttributeError as e:
            logging.error(f"Error fetching admin user: {e}")
            admin_user = None  # Fallback: handle gracefully
        if admin_user is None:
            content += f"{message.author.mention} (Admin user could not be fetched)"
        else:
            content += f"{message.author.mention} {admin_user.mention}"

        # embed.content(content=content)

        logging.debug("Scan result sent with admin mention.")
    else:
        embed.description = f"✅ 이 파일은 안전한 것으로 보입니다."

    if not WEBHOOK_URL:
        logging.error("WEBHOOK_URL is not set in the environment variables.")
        return

    # Webhook에 
        
    payload = {
        "content" : content,
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

async def handle_scan_results(self, message, filename, file_size, stats, status_message, file_path):
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
            try:
                admin_user = await self.bot.fetch_user(ADMIN_USER_ID)
            except AttributeError as e:
                logging.error(f"Error fetching admin user: {e}")
                admin_user = None  # Fallback: handle gracefully

            if admin_user is None:
                content = f"{message.author.mention} (Admin user could not be fetched)"
            else:
                content = f"{message.author.mention} {admin_user.mention}"

            await send_detailed_message_via_webhook(self, message, filename, file_size, stats)
            await status_message.reply(content=content, embed=result_embed)
            logging.debug("Scan result sent with admin mention.")
        else:
            result_embed.description = f"✅ 이 파일은 안전한 것으로 보입니다."
            await send_detailed_message_via_webhook(self, message, filename, file_size, stats)
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

async def handle_link_scan_results(self, message, filename, file_size, stats, status_message, link):
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
        title="링크 검사 결과",
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
            result_embed.description = f"⚠️ 이 링크는 잠재적으로 위험할 수 있습니다!"
            # 관리자 맨션
            try:
                admin_user = await self.bot.fetch_user(ADMIN_USER_ID)
            except AttributeError as e:
                logging.error(f"Error fetching admin user: {e}")
                admin_user = None  # Fallback: handle gracefully

            if admin_user is None:
                content = f"{message.author.mention} (Admin user could not be fetched)"
            else:
                content = f"{message.author.mention} {admin_user.mention}"

            await send_detailed_message_via_webhook(message, filename, file_size, stats)
            await status_message.reply(content=content, embed=result_embed)
            logging.debug("Scan result sent with admin mention.")
        else:
            result_embed.description = f"✅ 이 링크는 안전한 것으로 보입니다."
            await send_detailed_message_via_webhook(message, filename, file_size, stats)
            await status_message.reply(content=message.author.mention, embed=result_embed)

            # 안전한 링크면 Discord 파일로 별도 전송
            await message.channel.send(content=f"{link}")
            logging.debug("Safe link sent as a separate message.")

    except Exception as e:
        logging.exception(f"Error while handling scan results: {e}")
        await message.channel.send(f"파일 `{filename}` 처리 중 오류가 발생했습니다: {str(e)}")