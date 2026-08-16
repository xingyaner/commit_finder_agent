import os
import re
import subprocess
import logging
from datetime import datetime, timezone, timedelta
from src.utils import timezone_normalize

logger = logging.getLogger("ECRCL_Engine")

def _is_initial_round() -> bool:
    """
    独立定位系统中，我们始终是在对当前失败日志进行首轮深入诊断
    """
    return True


def execute_ecrcl_localization(
        log_path: str,
        project_name: str,
        project_source_path: str,
        oss_fuzz_path: str,
        error_date: str,
        env_vars: dict
) -> dict:
    """
    物理定位引擎：提取失败区域并采集上下游时域候选 Commit。
    候选归因与排序交由 LLM 执行，本引擎不再进行证据图打分或启发式排序。
    """
    logger.info("=========================================================")
    logger.info(f"Starting ECRCL Localization Engine for {project_name}")
    logger.info("=========================================================")

    # 0. 时间归一化
    t_error_epoch = timezone_normalize(error_date)
    t_error_utc = datetime.fromtimestamp(t_error_epoch, tz=timezone.utc)

    # 1. 故障日志提取 (Phase 0)
    if not os.path.exists(log_path):
        return {"status": "error", "message": f"Log file not found: {log_path}"}

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_raw = f.read()

    val_marker = "--- 1+2+6 VALIDATION SUMMARY"
    raw_compile_zone = log_raw.split(val_marker)[0] if val_marker in log_raw else log_raw
    log_lines = raw_compile_zone.splitlines()

    matched_idx = -1
    for i in range(len(log_lines) - 1, -1, -1):
        if any(kw in log_lines[i].lower() for kw in ["error:", "cannot ", "fail", "undefined reference"]):
            matched_idx = i
            break

    if matched_idx == -1:
        for i in range(len(log_lines) - 1, -1, -1):
            if any(kw in log_lines[i].lower() for kw in ["warning:", "exit status"]):
                matched_idx = i
                break

    if matched_idx == -1:
        return {"status": "error", "message": "No build failure features detected."}

    start_idx = max(0, matched_idx - 30)
    end_idx = min(len(log_lines), matched_idx + 31)
    failure_region_text = "\n".join(log_lines[start_idx:end_idx])

    # 提取区域内的相关代码或配置文件
    path_pattern = r"([\w\-\./_]+\.(?:c|cpp|h|cc|cxx|rs|go|py|sh|java|swift|cmake|txt|yaml|json|PC|pc))"
    raw_filepaths = re.findall(path_pattern, failure_region_text)

    top_1_file = None
    for f_cand in raw_filepaths:
        if not any(sys_p in f_cand for sys_p in ["/usr/include/", "/.cargo/", "/.rustup/", "gcr.io/"]):
            if f_cand.endswith(('.c', '.cpp', '.cc', '.h', '.go', '.rs', '.sh', 'Dockerfile', 'build.sh', 'PC', 'pc')):
                top_1_file = f_cand
                break
    if not top_1_file:
        top_1_file = raw_filepaths[0] if raw_filepaths else "build.sh"

    line_match = re.search(rf"{re.escape(top_1_file)}:(\d+)", failure_region_text)

    # Phase 1: 时域滑动窗口过滤 (T_error ± 24h)
    since_date = (t_error_utc - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    until_date = (t_error_utc + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    def collect_commits(repo_path: str, origin: str, window_only: bool) -> list:
        if not os.path.exists(repo_path):
            return []
        try:
            if window_only:
                log_cmd = [
                    "git", "-C", repo_path, "log",
                    f"--since={since_date}", f"--until={until_date}",
                    "--pretty=format:%H|%ct|%an|%cd|%s"
                ]
            else:
                log_cmd = ["git", "-C", repo_path, "log", "-n", "10", "--pretty=format:%H|%ct|%an|%cd|%s"]
            git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
        except Exception as e:
            logger.error(f"Failed to query {origin.lower()} git logs: {e}")
            return []

        commits = []
        for line in git_res.stdout.splitlines():
            if not line:
                continue
            try:
                sha, epoch, author, date_str, msg = line.split('|', 4)
            except ValueError:
                continue
            changed_files = []
            try:
                files_res = subprocess.run(
                    ["git", "-C", repo_path, "show", "--name-only", "--format=", sha],
                    capture_output=True,
                    text=True,
                    check=True
                )
                changed_files = [f.strip() for f in files_res.stdout.splitlines() if f.strip()]
            except Exception as e:
                logger.warning(f"Failed to collect changed files for {sha}: {e}")
            commits.append({
                "sha": sha,
                "epoch": int(epoch),
                "author": author,
                "date": date_str,
                "message": msg,
                "changed_files": changed_files,
                "origin": origin,
                "workspace": repo_path,
                "selection_source": "time_window" if window_only else "recent_fallback"
            })
        return commits

    suspect_commits = []
    suspect_commits.extend(collect_commits(oss_fuzz_path, "DOWNSTREAM", window_only=True))
    suspect_commits.extend(collect_commits(project_source_path, "UPSTREAM", window_only=True))

    # 兜底获取最近 10 条（若时域内没有获取到任何记录）
    if not suspect_commits:
        logger.warning("No commits found in T_error ± 24h. Falling back to recent 10 commits from both repositories.")
        suspect_commits.extend(collect_commits(oss_fuzz_path, "DOWNSTREAM", window_only=False))
        suspect_commits.extend(collect_commits(project_source_path, "UPSTREAM", window_only=False))

    return {
        "status": "success",
        "candidate_commits": suspect_commits,
        "project_source_path": project_source_path,
        "oss_fuzz_path": oss_fuzz_path,
        "failure_region_text": failure_region_text,
        "top_1_file": top_1_file,
        "line_num": line_match.group(1) if line_match else "N/A",
        "time_window": {
            "since": since_date,
            "until": until_date,
            "fallback_used": bool(suspect_commits and suspect_commits[0].get("selection_source") == "recent_fallback")
        }
    }
