import os
import re
import subprocess
import logging
from datetime import datetime, timezone, timedelta
from src.utils import timezone_normalize, clamp_diff_content
from src.evidence_graph import EvidenceGraph

logger = logging.getLogger("ECRCL_Engine")

def execute_ecrcl_localization(
    log_path: str,
    project_name: str,
    project_source_path: str,
    oss_fuzz_path: str,
    error_date: str,
    env_vars: dict
) -> dict:
    """
    物理定位引擎：顺序执行 Phase 0 -> Phase 2.5 流程。
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

    # 2. 确定初始搜索工作区 (Phase 1)
    is_downstream = any(cfg in top_1_file for cfg in ["Dockerfile", "build.sh", "project.yaml", "oss-fuzz", "projects/"])
    active_workspace = os.path.abspath(oss_fuzz_path) if is_downstream else os.path.abspath(project_source_path)

    logger.info(f"Targeting active workspace: {active_workspace} based on file: {top_1_file}")

    suspect_commits = []
    blamed_sha = None

    # Phase 1.1: 行级 Blame 追踪
    line_match = re.search(rf"{re.escape(top_1_file)}:(\d+)", failure_region_text)
    if line_match and os.path.exists(active_workspace):
        line_num = int(line_match.group(1))
        file_abs_path = os.path.abspath(os.path.join(active_workspace, top_1_file))
        if os.path.exists(file_abs_path) and os.path.isfile(file_abs_path):
            try:
                with open(file_abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_len = sum(1 for _ in f)
                clamped_line = min(line_num, file_len) if file_len > 0 else 1
                blame_cmd = ["git", "-C", active_workspace, "blame", "-L", f"{clamped_line},{clamped_line}", "--porcelain", file_abs_path]
                res = subprocess.run(blame_cmd, capture_output=True, text=True, check=True)
                blamed_sha = res.stdout.splitlines()[0].split(' ')[0]
                logger.info(f"Precise Blame anchor matched: {blamed_sha}")
            except Exception as e:
                logger.warning(f"Git blame failed on precise line check: {e}")

    # Phase 1.3: 时域滑动窗口过滤 (T_error ± 24h)
    since_date = (t_error_utc - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    until_date = (t_error_utc + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    try:
        log_cmd = ["git", "-C", active_workspace, "log", f"--since={since_date}", f"--until={until_date}", "--pretty=format:%H|%ct|%an|%cd|%s"]
        git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
        for line in git_res.stdout.splitlines():
            if not line: continue
            sha, epoch, author, date_str, msg = line.split('|', 4)
            suspect_commits.append({
                "sha": sha, "epoch": int(epoch), "author": author,
                "date": date_str, "message": msg, "changed_files": []
            })
    except Exception as e:
        logger.error(f"Failed to query git logs: {e}")

    # 兜底
    if not suspect_commits:
        try:
            log_cmd = ["git", "-C", active_workspace, "log", "-n", "20", "--pretty=format:%H|%ct|%an|%cd|%s"]
            git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
            for line in git_res.stdout.splitlines():
                if not line: continue
                sha, epoch, author, date_str, msg = line.split('|', 4)
                suspect_commits.append({
                    "sha": sha, "epoch": int(epoch), "author": author,
                    "date": date_str, "message": msg, "changed_files": []
                })
        except Exception:
            pass

    # 3. 约束收缩过滤器 (Phase 2)
    C1 = []
    for c in suspect_commits:
        try:
            show_cmd = ["git", "-C", active_workspace, "show", "--name-only", "--format=", c["sha"]]
            files_res = subprocess.run(show_cmd, capture_output=True, text=True, check=True)
            c_files = [f.strip() for f in files_res.stdout.splitlines() if f.strip()]
            c["changed_files"] = c_files

            is_consistent = False
            for f in c_files:
                if os.path.basename(f) == os.path.basename(top_1_file):
                    is_consistent = True
                    break
                if any(cfg in f for cfg in ["Dockerfile", "build.sh", "Makefile", "CMakeLists.txt"]):
                    is_consistent = True
                    break
                if any(dep in f for dep in ["go.mod", "go.sum", "Cargo.toml", "package.json"]):
                    is_consistent = True
                    break
            if is_consistent:
                C1.append(c)
        except Exception:
            pass

    if len(C1) >= 1:
        suspect_commits = C1

    # 4. 构建异构证据图谱并运行信念传播 (Phase 2.5)
    active_shas = [c["sha"] for c in suspect_commits]
    commit_messages_map = {c["sha"]: c["message"] for c in suspect_commits}

    graph = EvidenceGraph()
    graph.add_node("Nregion", "Failure Region")

    for c in suspect_commits:
        c_node = f"Ncommit_{c['sha']}"
        graph.add_node(c_node, "Commit")
        
        msg_node = f"Nmsg_{c['sha']}"
        graph.add_node(msg_node, "Commit Message")
        graph.add_edge(msg_node, c_node, 1.0)

        if any(kw in c["message"].lower() for kw in ["error", "fail", "conflict", "compile", "fix"]):
            graph.add_edge("Nregion", msg_node, 1.1)

        for f in c["changed_files"]:
            f_node = f"Nfile_{f}"
            graph.add_node(f_node, "File")
            
            dt = abs(c["epoch"] - t_error_epoch)
            decay_weight = max(0.1, 1.5 * (0.5 ** (dt / 86400.0)))
            graph.add_edge(f_node, c_node, decay_weight)

            if os.path.basename(f) == os.path.basename(top_1_file):
                graph.add_edge("Nregion", f_node, 1.3)

        if blamed_sha and c["sha"] == blamed_sha:
            graph.add_edge("Nregion", c_node, 1.5)

    scores = graph.run_belief_propagation(active_shas, env_vars, commit_messages_map)
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    return {
        "status": "success",
        "sorted_scores": sorted_scores,
        "is_downstream": is_downstream,
        "active_workspace": active_workspace,
        "project_source_path": project_source_path,  # 新增上游源码路径
        "oss_fuzz_path": oss_fuzz_path,  # 新增下游oss-fuzz路径
        "failure_region_text": failure_region_text,
        "top_1_file": top_1_file,
        "line_num": line_match.group(1) if line_match else "N/A"
    }
