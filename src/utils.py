import os
import yaml
import tempfile
import sys
import urllib
import urllib.request
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

def update_yaml_report(
    file_path: str,
    row_index: int,
    result: str,
    commit: str = None,
    workspace: str = None
) -> dict:
    """
    更新独立根因定位系统中的 YAML 报表。
    1. 标记处理状态为 state: 'yes' 并记录定位结果 (Success/Failure) 与日期。
    2. 如果定位成功 (result == "Success")，自动将 root_cause_commit 和 root_cause_workspace
       物理插入在 error_category 与 state 之间。
    3. 通过临时文件原子替换(Atomic Swap) + allow_unicode 保证写入安全，杜绝乱码与数据损坏。
    """
    print(f"--- Tool: update_yaml_report called for file '{file_path}', index {row_index} ---")
    try:
        if not os.path.exists(file_path):
            return {'status': 'error', 'message': f"YAML file not found at '{file_path}'."}

        # 1. 安全读取原始 YAML 数据
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if row_index < 0 or row_index >= len(data):
            return {'status': 'error', 'message': f"Invalid row index: {row_index}."}

        old_item = data[row_index]
        is_success = (result.lower() == "success")

        # 2. 构建保序新对象 (Order-Preserving Key Manipulation)
        updated_item = {}
        has_fixed_state = 'fixed_state' in old_item

        for k, v in old_item.items():
            if k == 'fixed_state':
                # 物理删除旧的 fixed_state 字段，并在该位置替换为新标记
                updated_item['state'] = 'yes'
                updated_item['fix_result'] = result
                updated_item['fix_date'] = datetime.now().strftime('%Y-%m-%d')
            else:
                updated_item[k] = v

            # 核心定位：当遇到 error_category 且定位成功时，在其后方立即插入定位数据
            if k == 'error_category' and is_success:
                updated_item['root_cause_commit'] = commit if commit else "UNKNOWN"
                updated_item['root_cause_workspace'] = workspace if workspace else "UNKNOWN"

        # 防御性补丁：若原始 YAML 中意外缺失 fixed_state 键，将其追加在末尾
        if not has_fixed_state:
            updated_item['state'] = 'yes'
            updated_item['fix_result'] = result
            updated_item['fix_date'] = datetime.now().strftime('%Y-%m-%d')

        # 3. 覆盖原始列表对应的索引位置
        data[row_index] = updated_item

        # 4. 🔑 物理原子写入 (Atomic File Write & Swap)
        dir_name = os.path.dirname(os.path.abspath(file_path))
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".projects_yaml_tmp_", suffix=".yaml")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp_f:
                # sort_keys=False 必须保持，以锁定我们构建的保序字典物理顺序
                yaml.dump(data, tmp_f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            os.replace(tmp_path, file_path)  # 物理原子级覆盖，杜绝写盘中途中断导致原文件损坏
        except Exception as swap_e:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise swap_e

        message = f"Successfully updated project at index {row_index} in '{file_path}'."
        print(message)
        return {'status': 'success', 'message': message}
    except Exception as e:
        message = f"Failed to update YAML report cleanly: {e}"
        print(f"--- ERROR: {message} ---")
        return {'status': 'error', 'message': message}
