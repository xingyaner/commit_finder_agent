import sys
import urllib
import urllib.request
import os
import logging
from datetime import datetime, timezone, timedelta

# 配置高内聚日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("CommitFinderUtils")


def download_log_from_url(url: str, dest_path: str) -> bool:
    """
    自愈式远程日志下载器：
    自动捕获远程 GCS 构建日志 URL 并流式写入本地 build_error_log 目录中。
    """
    try:
        logger.info(f"Downloading remote failure log: {url}")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        # 🔑 使用显式导入的 urllib.request
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=45) as response:
            with open(dest_path, 'wb') as out_file:
                out_file.write(response.read())
        logger.info("Log file successfully downloaded and stored locally.")
        return True
    except Exception as e:
        logger.error(f"Failed to download remote log file: {e}")
        return False


def timezone_normalize(error_date: str) -> int:
    """
    将多样化的时间格式 (CST UTC+8) 转换为 UTC 标准 naive Epoch 时间戳。
    确保在 Git 历史分析中时序对齐无偏差。
    """
    try:
        tz_cst = timezone(timedelta(hours=8))
        clean_date = error_date.strip().replace('.', '-').replace('/', '-')
        
        if ' ' in clean_date:
            t_error_naive = datetime.strptime(clean_date, "%Y-%m-%d %H:%M:%S")
        else:
            t_error_naive = datetime.strptime(clean_date, "%Y-%m-%d")
            
        t_error_cst = t_error_naive.replace(tzinfo=tz_cst)
        t_error_utc = t_error_cst.astimezone(timezone.utc)
        return int(t_error_utc.timestamp())
    except Exception as e:
        logger.warning(f"Failed to normalize error_date '{error_date}': {e}. Falling back to now.")
        return int(datetime.now(timezone.utc).timestamp())

def clamp_diff_content(diff_text: str) -> str:
    """
    Token 保护机制：
    1. 单个文件差异变动超过 3000 字符时，强制剔除上下文行，仅保留 Hunk Header、+ 和 - 标志行。
    2. 总差异内容超过 10000 字符时，进行强剪枝。
    """
    if not diff_text:
        return ""

    file_blocks = []
    current_block = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_block:
                file_blocks.append("\n".join(current_block))
            current_block = [line]
        else:
            current_block.append(line)
    if current_block:
        file_blocks.append("\n".join(current_block))

    clamped_blocks = []
    for block in file_blocks:
        if len(block) > 3000:
            lines = block.splitlines()
            pruned_lines = [
                l for l in lines
                if l.startswith(('+', '-', '@', 'diff --git ', '--- ', '+++ ', 'index '))
            ]
            clamped_block = "\n".join(pruned_lines)
            if len(clamped_block) > 3000:
                clamped_block = clamped_block[:3000] + "\n... [Single File Diff Truncated] ..."
            clamped_blocks.append(clamped_block)
        else:
            clamped_blocks.append(block)

    final_diff = "\n".join(clamped_blocks)

    if len(final_diff) > 10000:
        lines = final_diff.splitlines()
        shrunk_lines = [
            l for l in lines
            if l.startswith(('+', '-', '@', 'diff --git ', 'commit ', 'Author:', 'Date:', 'Subject:'))
        ]
        final_diff = "\n".join(shrunk_lines)
        if len(final_diff) > 10000:
            final_diff = final_diff[:10000] + "\n... [Total Diff Truncated for Token safety] ..."

    return final_diff
