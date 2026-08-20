import os
import sys
import yaml
import json
import logging
import subprocess
from datetime import datetime
from dotenv import load_dotenv
# 🌟 引入 update_yaml_report 用于回填
from src.utils import (
    timezone_normalize,
    clamp_diff_content,
    download_log_from_url,
    update_yaml_report,
    clear_root_cause_report,
)
from src.workspace import WorkspaceManager
from src.ecrcl_engine import execute_ecrcl_localization
from src.agent import CognitiveAgent

# 加载 .env 配置
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("StandaloneCommitFinder")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


class TeeStream:
    def __init__(self, primary, secondary):
        self.primary = primary
        self.secondary = secondary

    def write(self, data):
        self.primary.write(data)
        self.secondary.write(data)

    def flush(self):
        self.primary.flush()
        self.secondary.flush()

    def isatty(self):
        return self.primary.isatty()


def start_project_log(project_name: str) -> dict:
    safe_project = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in project_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(PROJECT_ROOT, "project_run_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{safe_project}_{timestamp}_log.txt")
    log_file = open(log_path, "a", encoding="utf-8", buffering=1)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] (%(name)s) %(message)s"))
    logging.getLogger().addHandler(file_handler)

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeStream(original_stdout, log_file)
    sys.stderr = TeeStream(original_stderr, log_file)

    logger.info(f"Project run log started: {log_path}")
    return {
        "path": log_path,
        "file": log_file,
        "handler": file_handler,
        "stdout": original_stdout,
        "stderr": original_stderr
    }


def stop_project_log(project_log: dict):
    if not project_log:
        return
    logger.info(f"Project run log finished: {project_log['path']}")
    sys.stdout = project_log["stdout"]
    sys.stderr = project_log["stderr"]
    root_logger = logging.getLogger()
    root_logger.removeHandler(project_log["handler"])
    project_log["handler"].close()
    project_log["file"].close()


def build_commit_details(candidate_commits: list, selected_shas: list) -> list:
    """
    Fetch detailed commit context only for the LLM-selected short list.
    """
    candidate_by_sha = {c.get("sha"): c for c in candidate_commits}
    detailed = []
    for sha in selected_shas:
        base = candidate_by_sha.get(sha)
        if not base:
            continue
        workspace = base.get("workspace")
        detail = {
            "sha": sha,
            "origin": base.get("origin"),
            "date": base.get("date"),
            "author": base.get("author"),
            "title": base.get("message"),
            "changed_files": base.get("changed_files", []),
            "diff": "",
            "stat": ""
        }
        try:
            stat_res = subprocess.run(
                ["git", "-C", workspace, "show", "--stat", "--summary", "--format=fuller", sha],
                capture_output=True,
                text=True,
                check=True
            )
            detail["stat"] = clamp_diff_content(stat_res.stdout)
        except Exception as e:
            logger.warning(f"Failed to extract stat for candidate {sha}: {e}")
        try:
            diff_res = subprocess.run(
                ["git", "-C", workspace, "show", "-U3", "--format=fuller", sha],
                capture_output=True,
                text=True,
                check=True
            )
            detail["diff"] = clamp_diff_content(diff_res.stdout)
        except Exception as e:
            logger.warning(f"Failed to extract diff for candidate {sha}: {e}")
        detailed.append(detail)
    return detailed


# 🌟 新增：独立定位环境清理工具函数
def cleanup_environment(project_name: str, upstream_path: str, downstream_path: str):
    """
    在一个项目处理结束之后（不论成功、失败或异常退出），
    1. 彻底递归删除已下载的上游第三方源码仓库以释放磁盘空间。
    2. 强制重置下游 oss-fuzz 仓库至干净场景。
    """
    import shutil
    import subprocess
    logger.info(f"--- 🧹 Cleaning workspace environment for project: {project_name} ---")

    # 1. 递归删除上游开源第三方仓库
    if os.path.exists(upstream_path):
        try:
            shutil.rmtree(upstream_path)
            logger.info(f"  - Successfully deleted upstream repository: {upstream_path}")
        except Exception as e:
            logger.warning(f"  - Warning: Failed to delete upstream repository {upstream_path}: {e}")

    # 2. 物理重置下游 oss-fuzz 仓库至干净场景
    if os.path.exists(downstream_path):
        try:
            # 强行还原所有被反事实测试或本地 patch 修改的文件
            subprocess.run(["git", "-C", downstream_path, "reset", "--hard", "HEAD"], capture_output=True)
            # 清除一切未跟踪的临时构建残留（如 CMake 临时文件或 Docker 构建缓存中间物）
            subprocess.run(["git", "-C", downstream_path, "clean", "-ffdx"], capture_output=True)
            logger.info(f"  - Successfully restored downstream oss-fuzz to clean state: {downstream_path}")
        except Exception as e:
            logger.warning(f"  - Warning: Failed to restore downstream git state: {e}")


def validate_commit_as_root_cause(local_workspace: WorkspaceManager, active_workspace: str,
                                  candidate_sha: str, project_name: str,
                                  project_source_path: str, origin_type: str,
                                  project_config: dict) -> bool:
    """Validate candidate B using the same A-pass/B-fail rule for both origins."""
    mount_path = None if origin_type == "DOWNSTREAM" else project_source_path
    try:
        parent_sha = subprocess.run(
            ["git", "-C", active_workspace, "rev-parse", f"{candidate_sha}^"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        for sha, expected_success in ((parent_sha, True), (candidate_sha, False)):
            subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"],
                           capture_output=True, check=True)
            subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"],
                           capture_output=True, check=True)
            subprocess.run(["git", "-C", active_workspace, "checkout", "--detach", sha],
                           capture_output=True, check=True)
            build_ok = local_workspace.execute_docker_compile(
                project_name=project_name,
                upstream_mount_path=mount_path,
                engine=project_config["engine"],
                sanitizer=project_config["sanitizer"],
                architecture=project_config["architecture"],
                environment_lock=project_config
            )
            if build_ok != expected_success:
                return False
        return True
    except Exception as e:
        logger.warning(f"Existing root-cause verification failed for {candidate_sha}: {e}")
        return False
    finally:
        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
        subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"], capture_output=True)


class StandalonePipeline:
    """
    负责循环读取 projects.yaml, 准备本地代码环境并调用 ECRCL 核心。
    """

    def __init__(self, config_yaml: str = None):
        if config_yaml is None:
            self.config_yaml = os.path.join(PROJECT_ROOT, "projects.yaml")
        else:
            self.config_yaml = os.path.abspath(config_yaml)

    def load_projects_config(self) -> list:
        if not os.path.exists(self.config_yaml):
            logger.error(f"Configuration file {self.config_yaml} not found!")
            return []
        with open(self.config_yaml, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("projects", [])
            return []

    def run_pipeline(self):
        projects = self.load_projects_config()
        if not projects:
            logger.warning("No projects to analyze in projects.yaml.")
            return

        consolidated_results = []
        output_results_dir = os.path.join(PROJECT_ROOT, "output_results")
        os.makedirs(output_results_dir, exist_ok=True)

        for row_index, proj in enumerate(projects):
            if not isinstance(proj, dict):
                logger.warning(f"Skipping malformed entry: {proj}")
                continue

            project_name = proj.get("project") or proj.get("project_name")
            oss_fuzz_sha = proj.get("oss-fuzz_sha") or proj.get("sha")
            raw_log_path = proj.get("fuzzing_build_error_log") or proj.get("original_log_path")
            software_sha = proj.get("software_sha")
            software_repo_url = proj.get("software_repo_url")

            if not project_name:
                logger.warning(f"Skipping entry missing project name key: {proj}")
                continue

            existing_root_sha = proj.get("root_cause_commit")
            existing_root_origin = str(proj.get("root_cause_workspace", "")).upper()
            has_existing_root = bool(
                existing_root_sha and existing_root_sha != "UNKNOWN" and
                existing_root_origin in {"UPSTREAM", "DOWNSTREAM"}
            )
            state_flag = proj.get("state") or proj.get("fixed_state")
            # state: yes is the durable processed marker. Existing root-cause
            # metadata is revalidated only while the row is still unprocessed.
            if state_flag == "yes":
                logger.info(f"Skipping project '{project_name}' (already processed with state: 'yes')")
                continue

            if not oss_fuzz_sha or not raw_log_path:
                logger.warning(f"Skipping {project_name} due to missing sha or log path metadata.")
                continue

            local_workspace = WorkspaceManager(base_dir=os.path.join(PROJECT_ROOT, "temp_workspaces"))
            oss_fuzz_path = local_workspace.get_downstream_path()
            project_source_path = local_workspace.get_upstream_path(project_name)
            project_log = start_project_log(project_name)

            try:
                logger.info(f"\nProcessing project context: {project_name}")
                local_agent = CognitiveAgent()

                local_workspace.clone_or_update_repo(
                    repo_url="https://github.com/google/oss-fuzz.git",
                    dest_path=oss_fuzz_path,
                    checkout_sha=oss_fuzz_sha
                )

                local_workspace.clone_or_update_repo(
                    repo_url=software_repo_url,
                    dest_path=project_source_path,
                    checkout_sha=software_sha
                )

                if has_existing_root:
                    active_workspace = (
                        project_source_path if existing_root_origin == "UPSTREAM" else oss_fuzz_path
                    )
                    logger.info(
                        "Existing root-cause check: %s (%s)",
                        existing_root_sha,
                        existing_root_origin
                    )
                    existing_verified = validate_commit_as_root_cause(
                        local_workspace=local_workspace,
                        active_workspace=active_workspace,
                        candidate_sha=existing_root_sha,
                        project_name=project_name,
                        project_source_path=project_source_path,
                        origin_type=existing_root_origin,
                        project_config=proj
                    )
                    if existing_verified:
                        logger.info("Existing root cause verified; marking project processed.")
                        update_yaml_report(
                            file_path=self.config_yaml,
                            row_index=row_index,
                            result="Success",
                            commit=existing_root_sha,
                            workspace=existing_root_origin
                        )
                        continue

                    logger.warning(
                        "Existing root cause %s failed; trying its parent as the replacement root cause.",
                        existing_root_sha
                    )
                    try:
                        parent_sha = subprocess.run(
                            ["git", "-C", active_workspace, "rev-parse", f"{existing_root_sha}^"],
                            capture_output=True, text=True, check=True
                        ).stdout.strip()
                    except Exception as parent_err:
                        logger.warning("Cannot resolve parent of existing root cause: %s", parent_err)
                        parent_sha = None

                    parent_verified = bool(parent_sha) and validate_commit_as_root_cause(
                        local_workspace=local_workspace,
                        active_workspace=active_workspace,
                        candidate_sha=parent_sha,
                        project_name=project_name,
                        project_source_path=project_source_path,
                        origin_type=existing_root_origin,
                        project_config=proj
                    )
                    if parent_verified:
                        logger.info("Parent of existing root cause verified; updating YAML.")
                        update_yaml_report(
                            file_path=self.config_yaml,
                            row_index=row_index,
                            result="Success",
                            commit=parent_sha,
                            workspace=existing_root_origin
                        )
                        continue

                    logger.warning(
                        "Existing root cause and its parent failed; clearing stale root cause and continuing localization."
                    )
                    clear_root_cause_report(self.config_yaml, row_index)
                    proj.pop("root_cause_commit", None)
                    proj.pop("root_cause_workspace", None)

                local_log_path = os.path.join(PROJECT_ROOT, "build_error_log", f"{project_name}_error.txt")
                if raw_log_path.startswith(("http://", "https://")):
                    success = download_log_from_url(raw_log_path, local_log_path)
                    if not success:
                        logger.error(f"Skipping {project_name} due to log download failure.")
                        update_yaml_report(self.config_yaml, row_index, "Failure")
                        continue
                    log_path = local_log_path
                else:
                    log_path = raw_log_path
                    if not os.path.isabs(log_path):
                        log_path = os.path.join(PROJECT_ROOT, log_path)

                ecrcl_result = execute_ecrcl_localization(
                    log_path=log_path,
                    project_name=project_name,
                    project_source_path=project_source_path,
                    oss_fuzz_path=oss_fuzz_path,
                    error_date=proj["error_time"],
                    env_vars=os.environ
                )

                if ecrcl_result.get("status") == "error":
                    logger.error(f"ECRCL engine failed for {project_name}: {ecrcl_result['message']}")
                    update_yaml_report(self.config_yaml, row_index, "Failure")
                    continue

                llm_attribution = local_agent.infer_attribution_workspace(
                    project_name=project_name,
                    failure_region_text=ecrcl_result["failure_region_text"],
                    top_1_file=ecrcl_result["top_1_file"]
                )
                logger.info(
                    f"LLM attribution decision: {llm_attribution['attribution_type']} "
                    f"({llm_attribution['confidence']}) - {llm_attribution['reason']}"
                )

                candidate_commits = ecrcl_result.get("candidate_commits", [])
                if not candidate_commits:
                    logger.error(f"No candidate commits collected for project {project_name}.")
                    update_yaml_report(self.config_yaml, row_index, "Failure")
                    continue

                # Attribution constrains the search space.  The LLM still chooses
                # the SHA and its ordering within that space, but it must not
                # select a commit from the other repository.
                attributed_candidates = [
                    candidate for candidate in candidate_commits
                    if str(candidate.get("origin", "")).upper() ==
                    llm_attribution["attribution_type"]
                ]
                if not attributed_candidates:
                    logger.error(
                        "No candidate commits match attribution %s; refusing to "
                        "replay candidates from the other workspace.",
                        llm_attribution["attribution_type"]
                    )
                    update_yaml_report(self.config_yaml, row_index, "Failure")
                    continue

                logger.info(
                    "Candidate pool constrained by attribution %s: %d/%d candidates",
                    llm_attribution["attribution_type"],
                    len(attributed_candidates),
                    len(candidate_commits)
                )

                initial_selected_shas = local_agent.select_initial_suspects(
                    project_name=project_name,
                    failure_region_text=ecrcl_result["failure_region_text"],
                    candidate_commits=attributed_candidates,
                    max_count=4
                )
                logger.info(f"LLM initial suspect set: {initial_selected_shas}")

                detailed_candidates = build_commit_details(candidate_commits, initial_selected_shas)
                logger.info(
                    "Detailed candidate set built for final LLM selection: "
                    f"{[c.get('sha') for c in detailed_candidates]}"
                )
                final_selected_shas = local_agent.select_final_suspects(
                    project_name=project_name,
                    failure_region_text=ecrcl_result["failure_region_text"],
                    detailed_candidates=detailed_candidates,
                    max_count=2
                )
                logger.info(f"LLM final replay set: {final_selected_shas}")

                candidate_by_sha = {c.get("sha"): c for c in attributed_candidates}
                suspect_pool = [candidate_by_sha[sha] for sha in final_selected_shas if sha in candidate_by_sha]

                final_suspect = "UNKNOWN"
                confidence = "LOW"
                validation_status = "FAIL"

                winning_workspace = "UNKNOWN"
                winning_origin = "UNKNOWN"
                verification_passed = False

                if not suspect_pool:
                    logger.error(f"LLM did not select any valid candidate commits for project {project_name}.")

                for attempt_idx, suspect_dict in enumerate(suspect_pool):
                    suspect = suspect_dict["sha"]
                    origin_type = suspect_dict["origin"]
                    active_workspace = suspect_dict["workspace"]
                    is_downstream_commit = (origin_type == "DOWNSTREAM")

                    logger.info(
                        f"--- [Phase 3] Verification Attempt {attempt_idx + 1}/{len(suspect_pool)}: Testing suspect {suspect} ({origin_type}) ---")
                    try:
                        # Both origins use the same causal test:
                        # parent A must build, and candidate B must fail.
                        # The only difference is whether the fixed upstream source
                        # is mounted while testing the OSS-Fuzz repository.
                        mount_path = None if is_downstream_commit else project_source_path

                        logger.info(f"Step 3.1: Validating father state ({suspect}^)...")
                        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"],
                                       capture_output=True, check=True)
                        subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"],
                                       capture_output=True, check=True)
                        subprocess.run(["git", "-C", active_workspace, "checkout", "--detach", f"{suspect}^"],
                                       capture_output=True, check=True)
                        parent_passed = local_workspace.execute_docker_compile(
                            project_name=project_name,
                            upstream_mount_path=mount_path,
                            engine=proj["engine"],
                            sanitizer=proj["sanitizer"],
                            architecture=proj["architecture"],
                            environment_lock=proj
                        )

                        logger.info(f"Step 3.2: Validating son state ({suspect})...")
                        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"],
                                       capture_output=True, check=True)
                        subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"],
                                       capture_output=True, check=True)
                        subprocess.run(["git", "-C", active_workspace, "checkout", "--detach", suspect],
                                       capture_output=True, check=True)
                        suspect_failed = not local_workspace.execute_docker_compile(
                            project_name=project_name,
                            upstream_mount_path=mount_path,
                            engine=proj["engine"],
                            sanitizer=proj["sanitizer"],
                            architecture=proj["architecture"],
                            environment_lock=proj
                        )

                        if parent_passed and suspect_failed:
                            validation_status = "PASS"
                            confidence = "HIGH"
                            final_suspect = suspect
                            winning_workspace = active_workspace
                            winning_origin = origin_type
                            verification_passed = True
                            logger.info(f"Causal Counterfactual validation PASSED on Attempt {attempt_idx + 1}!")
                            break
                        else:
                            logger.warning(
                                f"Attempt {attempt_idx + 1} failed. Suspect {suspect} did not satisfy verification criteria.")
                    except Exception as val_err:
                        logger.error(f"Replay validation hit unexpected error on {suspect}: {val_err}")
                    finally:
                        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                        subprocess.run(["git", "-C", active_workspace, "clean", "-fxd"], capture_output=True)

                if not verification_passed:
                    logger.error(
                        f"All {len(suspect_pool)} localization attempts failed for project {project_name}. Tagging as 'Failed'.")
                    final_suspect = "UNKNOWN"
                    confidence = "LOW"
                    validation_status = "FAIL"

                diff_text = ""
                target_author = "N/A"
                target_date = "N/A"
                target_title = "N/A"
                before_line = "N/A"
                after_line = "N/A"

                if final_suspect != "UNKNOWN":
                    try:
                        show_meta = ["git", "-C", winning_workspace, "show", "--pretty=format:%an|%ad|%s", "-s", final_suspect]
                        meta_res = subprocess.run(show_meta, capture_output=True, text=True, check=True)
                        target_author, target_date, target_title = meta_res.stdout.strip().split('|', 2)
                    except Exception:
                        pass

                    try:
                        diff_res = subprocess.run(["git", "-C", winning_workspace, "show", "-U3", final_suspect], capture_output=True, text=True, check=True)
                        diff_text = clamp_diff_content(diff_res.stdout)

                        removed_lines = [l[1:].strip() for l in diff_res.stdout.splitlines() if l.startswith('-') and not l.startswith('---')]
                        added_lines = [l[1:].strip() for l in diff_res.stdout.splitlines() if l.startswith('+') and not l.startswith('+++')]
                        if removed_lines: before_line = removed_lines[0]
                        if added_lines: after_line = added_lines[0]
                    except Exception:
                        diff_text = "Failed to extract commit diff context."

                # 🌟 修复：仅保留这套高精度、带 winning_origin 动态映射的认知处理与工件归档流程，彻底干掉冗余的重复代码
                attribution_type = winning_origin if final_suspect != "UNKNOWN" else llm_attribution["attribution_type"]
                arbitration_payload = {
                    "failure_region_text": ecrcl_result["failure_region_text"],
                    "final_suspect": final_suspect,
                    "confidence": confidence,
                    "attribution_type": attribution_type,
                    "top_1_file": ecrcl_result["top_1_file"],
                    "line_num": ecrcl_result["line_num"],
                    "diff_text": diff_text,
                    "validation_status": validation_status,
                    "target_author": target_author,
                    "target_date": target_date,
                    "target_title": target_title,
                    "before_line": before_line,
                    "after_line": after_line
                }

                logger.info("Calling Cognitive Agent to synthesize causal chain and final summary...")
                report_body = local_agent.execute_arbitration(
                    context_data=arbitration_payload,
                    instruction_path=os.path.join(PROJECT_ROOT, "instructions", "commit_finder_instruction.txt")
                )

                output_file_name = os.path.join(output_results_dir, f"{project_name}_commit_changed.txt")
                with open(output_file_name, 'w', encoding='utf-8') as out_f:
                    out_f.write(report_body.strip())
                logger.info(f"Report saved: {output_file_name}")

                consolidated_results.append({
                    "project_name": project_name,
                    "root_cause_commit": final_suspect,
                    "confidence_score": confidence,
                    "attribution_type": attribution_type,
                    "counterfactual_replay": validation_status,
                    "target_file": ecrcl_result["top_1_file"],
                    "line_num": ecrcl_result["line_num"]
                })

                if verification_passed and final_suspect != "UNKNOWN":
                    update_yaml_report(
                        file_path=self.config_yaml,
                        row_index=row_index,
                        result="Success",
                        commit=final_suspect,
                        workspace=attribution_type
                    )
                else:
                    update_yaml_report(
                        file_path=self.config_yaml,
                        row_index=row_index,
                        result="Failure"
                    )

            except Exception as crash_err:
                logger.error(f"CRITICAL: StandalonePipeline execution crashed for {project_name}: {crash_err}")
                # A preparation/runtime crash (for example a transient Git
                # clone failure) is not a completed root-cause check. Keep the
                # row retryable instead of marking it state: yes.

            finally:
                cleanup_environment(project_name, project_source_path, oss_fuzz_path)
                stop_project_log(project_log)

        consolidated_json_path = os.path.join(output_results_dir, "consolidated_results.json")
        with open(consolidated_json_path, 'w', encoding='utf-8') as j_f:
            json.dump(consolidated_results, j_f, indent=2, ensure_ascii=False)
        logger.info("All projects analyzed. Pipeline finished successfully.")

if __name__ == "__main__":
    pipeline = StandalonePipeline()
    pipeline.run_pipeline()
