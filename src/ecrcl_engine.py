import os
import re
import subprocess
import logging
from datetime import datetime, timezone, timedelta
from src.utils import timezone_normalize, clamp_diff_content
from src.evidence_graph import EvidenceGraph

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
    物理定位引擎：顺序执行 Phase 0 -> Phase 2.5 流程。
    集成双仓库全量时间窗口 Commit 堆叠赋分机制，不执行物理删除，仅通过评分进行优先级排序。
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

    # =================================================================
    # Phase 1: 观察受限的时域定位 (Observation-Bounded Temporal Localization)
    # 堆叠拉取上游源码与下游 oss-fuzz 的全部提交
    # =================================================================
    is_downstream = any(
        cfg in top_1_file for cfg in ["Dockerfile", "build.sh", "project.yaml", "oss-fuzz", "projects/"])
    blame_workspace = os.path.abspath(oss_fuzz_path) if is_downstream else os.path.abspath(project_source_path)

    suspect_commits = []
    blamed_sha = None

    # Phase 1.1: 行级 Blame 追踪
    line_match = re.search(rf"{re.escape(top_1_file)}:(\d+)", failure_region_text)
    if line_match and os.path.exists(blame_workspace):
        line_num = int(line_match.group(1))
        file_abs_path = os.path.abspath(os.path.join(blame_workspace, top_1_file))
        if os.path.exists(file_abs_path) and os.path.isfile(file_abs_path):
            try:
                with open(file_abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_len = sum(1 for _ in f)
                clamped_line = min(line_num, file_len) if file_len > 0 else 1
                blame_cmd = ["git", "-C", blame_workspace, "blame", "-L", f"{clamped_line},{clamped_line}",
                             "--porcelain", file_abs_path]
                res = subprocess.run(blame_cmd, capture_output=True, text=True, check=True)
                blamed_sha = res.stdout.splitlines()[0].split(' ')[0]
                logger.info(f"Precise Blame anchor matched: {blamed_sha}")
            except Exception as e:
                logger.warning(f"Git blame failed on precise line check: {e}")

    # Phase 1.3: 时域滑动窗口过滤 (T_error ± 24h)
    since_date = (t_error_utc - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    until_date = (t_error_utc + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    # A. 提取下游仓库中的时间窗口 Commit
    if os.path.exists(oss_fuzz_path):
        try:
            log_cmd = ["git", "-C", oss_fuzz_path, "log", f"--since={since_date}", f"--until={until_date}",
                       "--pretty=format:%H|%ct|%an|%cd|%s"]
            git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
            for line in git_res.stdout.splitlines():
                if not line: continue
                sha, epoch, author, date_str, msg = line.split('|', 4)
                suspect_commits.append({
                    "sha": sha, "epoch": int(epoch), "author": author,
                    "date": date_str, "message": msg, "changed_files": [],
                    "origin": "DOWNSTREAM", "workspace": oss_fuzz_path,
                    "score": 10.0  # 基础分：时间窗口命中
                })
        except Exception as e:
            logger.error(f"Failed to query downstream git logs: {e}")

    # B. 提取上游项目中的时间窗口 Commit
    if os.path.exists(project_source_path):
        try:
            log_cmd = ["git", "-C", project_source_path, "log", f"--since={since_date}", f"--until={until_date}",
                       "--pretty=format:%H|%ct|%an|%cd|%s"]
            git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
            for line in git_res.stdout.splitlines():
                if not line: continue
                sha, epoch, author, date_str, msg = line.split('|', 4)
                suspect_commits.append({
                    "sha": sha, "epoch": int(epoch), "author": author,
                    "date": date_str, "message": msg, "changed_files": [],
                    "origin": "UPSTREAM", "workspace": project_source_path,
                    "score": 10.0  # 基础分：时间窗口命中
                })
        except Exception as e:
            logger.error(f"Failed to query upstream git logs: {e}")

    # C. 兜底获取最近 10 条（若时域内没有获取到任何记录）
    if not suspect_commits:
        # 下游
        if os.path.exists(oss_fuzz_path):
            try:
                log_cmd = ["git", "-C", oss_fuzz_path, "log", "-n", "10", "--pretty=format:%H|%ct|%an|%cd|%s"]
                git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
                for line in git_res.stdout.splitlines():
                    if not line: continue
                    sha, epoch, author, date_str, msg = line.split('|', 4)
                    suspect_commits.append({
                        "sha": sha, "epoch": int(epoch), "author": author,
                        "date": date_str, "message": msg, "changed_files": [],
                        "origin": "DOWNSTREAM", "workspace": oss_fuzz_path,
                        "score": 5.0
                    })
            except Exception:
                pass
        # 上游
        if os.path.exists(project_source_path):
            try:
                log_cmd = ["git", "-C", project_source_path, "log", "-n", "10", "--pretty=format:%H|%ct|%an|%cd|%s"]
                git_res = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
                for line in git_res.stdout.splitlines():
                    if not line: continue
                    sha, epoch, author, date_str, msg = line.split('|', 4)
                    suspect_commits.append({
                        "sha": sha, "epoch": int(epoch), "author": author,
                        "date": date_str, "message": msg, "changed_files": [],
                        "origin": "UPSTREAM", "workspace": project_source_path,
                        "score": 5.0
                    })
            except Exception:
                pass

    # =================================================================
    # Phase 2: 顺序层级赋分 (Iterative Layered Scoring)
    # 所有检查不再直接移除 Commit，而是累积赋分，使通过的检查越多、分值越高
    # =================================================================

    for c in suspect_commits:
        ws = c["workspace"]

        # 🌟 第一级检查：Blame 匹配深度校验
        if blamed_sha and c["sha"] == blamed_sha:
            c["score"] += 50.0

        try:
            # 🌟 第二级检查：路径一致性赋分 (Step 2)
            show_cmd = ["git", "-C", ws, "show", "--name-only", "--format=", c["sha"]]
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
                c["score"] += 20.0  # 获得路径一致性评分

            # 🌟 第三级检查：语义相关性过滤赋分 (Step 3)
            msg_lower = c["message"].lower()
            positive_kws = ["build", "deps", "toolchain", "linker", "docker", "sanitizer", "fix", "upgrade"]
            negative_kws = ["docs", "readme", "typo", "formatting", "comment-only", "ci unrelated", "test-only"]

            if any(pos in msg_lower for pos in positive_kws):
                c["score"] += 15.0
            elif not any(neg in msg_lower for neg in negative_kws):
                c["score"] += 10.0

            # 🌟 第四级检查：代码差异（Diff）一致性特征赋分 (Step 4)
            diff_cmd = ["git", "-C", ws, "show", "-U0", "--format=", c["sha"]]
            diff_res = subprocess.run(diff_cmd, capture_output=True, text=True, check=True)
            diff_text = diff_res.stdout

            has_diff_feature = False
            if re.search(r"^[+-]\s*(?:#\s*include|import\s+|using\s+)", diff_text, re.MULTILINE):
                has_diff_feature = True
            elif re.search(r"^[+-]\s*(?:void|int|char|float|double|struct|class|public|fn)\s+\w+", diff_text,
                           re.MULTILINE):
                has_diff_feature = True
            elif any(flag in diff_text for flag in
                     ["-O", "-f", "-W", "-s", "sanitize", "LDFLAGS", "CFLAGS", "CXXFLAGS"]):
                has_diff_feature = True
            elif any(dep in diff_text for dep in ["rev", "version", "tag", "go ", "require "]):
                has_diff_feature = True

            if has_diff_feature:
                c["score"] += 15.0  # 获得差异一致性评分

        except Exception:
            pass

    # =================================================================
    # Phase 2.5: 跨提交证据图建模与信念传播迭代 (Evidence BP)
    # =================================================================
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

    bp_scores = graph.run_belief_propagation(active_shas, env_vars, commit_messages_map)

    # 🌟 将信念传播的图势能转化为量化评分加入到 Commit 中
    for c in suspect_commits:
        sha = c["sha"]
        bp_val = bp_scores.get(sha, 0.0)
        c["score"] += bp_val * 50.0  # 加入图传导得分
        c["bp_score"] = bp_val

    # 按照多维堆叠的最终累计得分排序
    sorted_scores = sorted([(c, c["score"]) for c in suspect_commits], key=lambda x: x[1], reverse=True)

    return {
        "status": "success",
        "sorted_scores": sorted_scores,
        "is_downstream": is_downstream,
        "project_source_path": project_source_path,
        "oss_fuzz_path": oss_fuzz_path,
        "failure_region_text": failure_region_text,
        "top_1_file": top_1_file,
        "line_num": line_match.group(1) if line_match else "N/A"
    }
