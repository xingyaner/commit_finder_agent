import os
import sys
import yaml
import json
import logging
import subprocess
from dotenv import load_dotenv
# 🌟 引入 update_yaml_report 用于回填
from src.utils import timezone_normalize, clamp_diff_content, download_log_from_url, update_yaml_report
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

            state_flag = proj.get("state") or proj.get("fixed_state")
            if state_flag == "yes":
                logger.info(f"Skipping project '{project_name}' (already processed with state: 'yes')")
                continue

            if not oss_fuzz_sha or not raw_log_path:
                logger.warning(f"Skipping {project_name} due to missing sha or log path metadata.")
                continue

            local_workspace = WorkspaceManager(base_dir=os.path.join(PROJECT_ROOT, "temp_workspaces"))
            oss_fuzz_path = local_workspace.get_downstream_path()
            project_source_path = local_workspace.get_upstream_path(project_name)

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

                sorted_scores = ecrcl_result["sorted_scores"]
                suspect_pool = [score_info[0] for score_info in sorted_scores[:10]] if sorted_scores else []

                final_suspect = "UNKNOWN"
                confidence = "LOW"
                validation_status = "FAIL"

                winning_workspace = "UNKNOWN"
                winning_origin = "UNKNOWN"
                verification_passed = False

                for attempt_idx, suspect_dict in enumerate(suspect_pool):
                    suspect = suspect_dict["sha"]
                    origin_type = suspect_dict["origin"]
                    active_workspace = suspect_dict["workspace"]
                    is_downstream_commit = (origin_type == "DOWNSTREAM")

                    logger.info(
                        f"--- [Phase 3] Verification Attempt {attempt_idx + 1}/{len(suspect_pool)}: Testing suspect {suspect} ({origin_type}) ---")
                    try:
                        if is_downstream_commit:
                            logger.info(f"Step3: Downstream commit, use revert counterfactual verify {suspect}")
                            revert_success = local_workspace.counterfactual_revert_downstream_commit(
                                repo_path=active_workspace,
                                target_commit=suspect,
                                project_name=project_name,
                                engine=proj["engine"],
                                sanitizer=proj["sanitizer"],
                                architecture=proj["architecture"]
                            )
                            parent_passed = revert_success
                            suspect_failed = True
                        else:
                            logger.info(f"Step 3.1: Validating parent state ({suspect}~1)...")
                            subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                            subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"], capture_output=True)
                            subprocess.run(["git", "-C", active_workspace, "checkout", f"{suspect}~1"], capture_output=True)
                            parent_passed = local_workspace.execute_docker_compile(
                                project_name=project_name,
                                upstream_mount_path=project_source_path,
                                engine=proj["engine"],
                                sanitizer=proj["sanitizer"],
                                architecture=proj["architecture"]
                            )
                            logger.info(f"Step 3.2: Validating suspect state ({suspect})...")
                            subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                            subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"], capture_output=True)
                            subprocess.run(["git", "-C", active_workspace, "checkout", suspect], capture_output=True)
                            suspect_failed = not local_workspace.execute_docker_compile(
                                project_name=project_name,
                                upstream_mount_path=project_source_path,
                                engine=proj["engine"],
                                sanitizer=proj["sanitizer"],
                                architecture=proj["architecture"]
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
                attribution_type = winning_origin if final_suspect != "UNKNOWN" else (
                    "DOWNSTREAM" if ecrcl_result["is_downstream"] else "UPSTREAM")
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
                update_yaml_report(self.config_yaml, row_index, "Failure")

            finally:
                cleanup_environment(project_name, project_source_path, oss_fuzz_path)

        consolidated_json_path = os.path.join(output_results_dir, "consolidated_results.json")
        with open(consolidated_json_path, 'w', encoding='utf-8') as j_f:
            json.dump(consolidated_results, j_f, indent=2, ensure_ascii=False)
        logger.info("All projects analyzed. Pipeline finished successfully.")

if __name__ == "__main__":
    pipeline = StandalonePipeline()
    pipeline.run_pipeline()
