import shutil
from discord.ext import commands
import logging
from pathlib import Path
from cogs.utils import get_server_settings, save_server_settings, TEMP_DIR, is_admin

class CommandCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="toggle", help="봇의 기능을 켜거나 끕니다")
    async def toggle_feature(self, ctx, feature: str):
        if not is_admin(ctx):
            await ctx.send("이 명령어는 관리자만 사용할 수 있습니다.")
            return

        guild_id = ctx.guild.id
        settings = get_server_settings(guild_id)

        if feature not in ["save_temp", "file_check", "link_check"]:
            await ctx.send("❌ 잘못된 기능 이름입니다. 사용 가능한 기능: save_temp, file_check, link_check")
            return

        current_value = getattr(settings, feature)
        new_value = not current_value
        setattr(settings, feature, new_value)

        save_server_settings()

        status = "활성화" if new_value else "비활성화"
        feature_names = {
            "save_temp": "임시 파일 저장",
            "file_check": "파일 검사",
            "link_check": "링크 검사"
        }

        await ctx.send(f"✅ {feature_names[feature]}이(가) {status}되었습니다.")
        logging.info(f"Feature {feature} toggled to {new_value} for server {guild_id}")

    @commands.command(name="clear", help="Temp 폴더를 초기화합니다")
    async def clear_temp(self, ctx):
        if not is_admin(ctx):
            await ctx.send("이 명령어는 관리자만 사용할 수 있습니다.")
            return

        try:
            for item in TEMP_DIR.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)

            await ctx.send("✅ Temp 폴더가 초기화되었습니다.")
            logging.info("Temp folder cleared successfully")
        except Exception as e:
            await ctx.send(f"❌ Temp 폴더 초기화 중 오류가 발생했습니다: {str(e)}")
            logging.error(f"Error clearing temp folder: {e}")

    @commands.command(name="set", help="봇 설정을 변경합니다 (!set <network_limit>)")
    async def set_network(self, ctx, network: int):
        if not is_admin(ctx):
            await ctx.send("이 명령어는 관리자만 사용할 수 있습니다.")
            return

        if network < 0:
            await ctx.send("❌ 네트워크 대역폭은 0 이상이어야 합니다.")
            return

        guild_id = ctx.guild.id
        settings = get_server_settings(guild_id)

        settings.network_limit = None if network == 0 else network
        save_server_settings()

        status_msg = "무제한" if network == 0 else f"{network}Mbps"
        await ctx.send(f"✅ 네트워크 대역폭이 {status_msg}으로 설정되었습니다.")
        logging.info(f"Network bandwidth limit set to {status_msg} for server {guild_id}")

async def setup(bot):
    await bot.add_cog(CommandCog(bot))