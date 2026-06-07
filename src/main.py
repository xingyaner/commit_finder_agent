import os
import sys
import yaml
import json
import logging
import subprocess
from dotenv import load_dotenv
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

        # 🌟 采用 enumerate 迭代解析，从而安全捕获当前项目在 projects.yaml 中的物理 row_index
        for row_index, proj in enumerate(projects):
            if not isinstance(proj, dict):
                logger.warning(f"Skipping malformed entry: {proj}")
                continue

            # 动态属性映射器 (兼容多种命名协议)
            project_name = proj.get("project") or proj.get("project_name")
            oss_fuzz_sha = proj.get("oss-fuzz_sha") or proj.get("sha")
            raw_log_path = proj.get("fuzzing_build_error_log") or proj.get("original_log_path")
            software_sha = proj.get("software_sha")
            software_repo_url = proj.get("software_repo_url")

            if not project_name:
                logger.warning(f"Skipping entry missing project name key: {proj}")
                continue
            if not oss_fuzz_sha or not raw_log_path:
                logger.warning(f"Skipping {project_name} due to missing sha or log path metadata.")
                continue

            logger.info(f"\nProcessing project context: {project_name}")

            # 🌟 方案二第 1 点实现（局部变量隔离）：将持久实例改造为项目级别物理隔离的局部对象
            local_workspace = WorkspaceManager(base_dir=os.path.join(PROJECT_ROOT, "temp_workspaces"))
            local_agent = CognitiveAgent()

            # 下载并对齐 Downstream 基础设施 (oss-fuzz)
            oss_fuzz_path = local_workspace.get_downstream_path()
            local_workspace.clone_or_update_repo(
                repo_url="https://github.com/google/oss-fuzz.git",
                dest_path=oss_fuzz_path,
                checkout_sha=oss_fuzz_sha
            )

            # 下载并对齐 Upstream 项目源码
            project_source_path = local_workspace.get_upstream_path(project_name)
            local_workspace.clone_or_update_repo(
                repo_url=software_repo_url,
                dest_path=project_source_path,
                checkout_sha=software_sha
            )

            # 动态处理远程日志下载与本地持久化
            local_log_path = os.path.join(PROJECT_ROOT, "build_error_log", f"{project_name}_error.txt")
            if raw_log_path.startswith(("http://", "https://")):
                success = download_log_from_url(raw_log_path, local_log_path)
                if not success:
                    logger.error(f"Skipping {project_name} due to log download failure.")
                    # 🌟 加固保护：若日志下载失败，同步向 YAML 报表回填 Failure 状态
                    update_yaml_report(self.config_yaml, row_index, "Failure")
                    continue
                log_path = local_log_path
            else:
                log_path = raw_log_path
                if not os.path.isabs(log_path):
                    log_path = os.path.join(PROJECT_ROOT, log_path)

            # 运行物理初筛与图建模计算 (ECRCL Phase 0 ~ 2.5)
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
                # 🌟 加固保护：若底层计算引擎异常，同步向 YAML 报表回填 Failure 状态
                update_yaml_report(self.config_yaml, row_index, "Failure")
                continue

            # 提取图评分前三嫌疑 Commit
            sorted_scores = ecrcl_result["sorted_scores"]
            suspect_pool = [score_info[0] for score_info in sorted_scores[:3]] if sorted_scores else []

            # 🔑 三级顺延校验状态机
            final_suspect = "UNKNOWN"
            confidence = "LOW"
            validation_status = "FAIL"
            active_workspace = ecrcl_result["active_workspace"]
            verification_passed = False

            for attempt_idx, suspect in enumerate(suspect_pool):
                logger.info(f"--- [Phase 3] Verification Attempt {attempt_idx + 1}/3: Testing suspect {suspect} ---")
                try:
                    if ecrcl_result["is_downstream"]:
                        # ==========下游commit：走revert反事实逻辑（新增分支）==========
                        logger.info(f"Step3: Downstream commit, use revert counterfactual verify {suspect}")
                        # 下游oss-fuzz目录，mount_path=None，仅回滚当前commit
                        revert_success = local_workspace.counterfactual_revert_downstream_commit(
                            repo_path=ecrcl_result["oss_fuzz_path"],
                            target_commit=suspect,
                            project_name=project_name,
                            engine=proj["engine"],
                            sanitizer=proj["sanitizer"],
                            architecture=proj["architecture"]
                        )
                        # 反事实规则：撤销下游commit后构建成功 → 原commit是故障根因
                        parent_passed = revert_success
                        suspect_failed = True
                    else:
                        # ==========上游源码commit：保留原有父提交校验逻辑不变==========
                        logger.info(f"Step 3.1: Validating parent state ({suspect}~1)...")
                        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                        subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"], capture_output=True)
                        subprocess.run(["git", "-C", active_workspace, "checkout", f"{suspect}~1"],
                                       capture_output=True)
                        parent_passed = local_workspace.execute_docker_compile(
                            project_name=project_name,
                            upstream_mount_path=project_source_path,
                            engine=proj["engine"],
                            sanitizer=proj["sanitizer"],
                            architecture=proj["architecture"]
                        )
                        # 4.2 校验嫌疑提交 (Expected FAIL)
                        logger.info(f"Step 3.2: Validating suspect state ({suspect})...")
                        subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                        subprocess.run(["git", "-C", active_workspace, "clean", "-ffdx"], capture_output=True)
                        subprocess.run(["git", "-C", active_workspace, "checkout", suspect],
                                       capture_output=True)
                        suspect_failed = not local_workspace.execute_docker_compile(
                            project_name=project_name,
                            upstream_mount_path=project_source_path,
                            engine=proj["engine"],
                            sanitizer=proj["sanitizer"],
                            architecture=proj["architecture"]
                        )

                    # 4.3 综合决策
                    if parent_passed and suspect_failed:
                        validation_status = "PASS"
                        confidence = "HIGH"
                        final_suspect = suspect
                        verification_passed = True
                        logger.info(f"Causal Counterfactual validation PASSED on Attempt {attempt_idx + 1}!")
                        break  # 验证通过，立即跳出重试
                    else:
                        logger.warning(
                            f"Attempt {attempt_idx + 1} failed. Suspect {suspect} did not satisfy verification criteria.")
                except Exception as val_err:
                    logger.error(f"Replay validation hit unexpected error on {suspect}: {val_err}")
                finally:
                    # 安全复原
                    subprocess.run(["git", "-C", active_workspace, "reset", "--hard", "HEAD"], capture_output=True)
                    subprocess.run(["git", "-C", active_workspace, "clean", "-fxd"], capture_output=True)

            if not verification_passed:
                logger.error(f"All 3 localization attempts failed for project {project_name}. Tagging as 'Failed'.")
                final_suspect = "UNKNOWN"
                confidence = "LOW"
                validation_status = "FAIL"

            # 5. 抓取嫌疑 Diff 及具体变更信息
            diff_text = ""
            target_author = "N/A"
            target_date = "N/A"
            target_title = "N/A"
            before_line = "N/A"
            after_line = "N/A"

            if final_suspect != "UNKNOWN":
                try:
                    show_meta = ["git", "-C", active_workspace, "show", "--pretty=format:%an|%ad|%s", "-s",
                                 final_suspect]
                    meta_res = subprocess.run(show_meta, capture_output=True, text=True, check=True)
                    target_author, target_date, target_title = meta_res.stdout.strip().split('|', 2)
                except Exception:
                    pass

                try:
                    diff_res = subprocess.run(["git", "-C", active_workspace, "show", "-U3", final_suspect],
                                              capture_output=True, text=True, check=True)
                    diff_text = clamp_diff_content(diff_res.stdout)

                    # 提取变更行快照 (Before/After)
                    removed_lines = [l[1:].strip() for l in diff_res.stdout.splitlines() if
                                     l.startswith('-') and not l.startswith('---')]
                    added_lines = [l[1:].strip() for l in diff_res.stdout.splitlines() if
                                   l.startswith('+') and not l.startswith('+++')]
                    if removed_lines: before_line = removed_lines[0]
                    if added_lines: after_line = added_lines[0]
                except Exception:
                    diff_text = "Failed to extract commit diff context."

            # 6. 唤醒认知仲裁 Agent 整合生成因果分析 (Phase 4)
            attribution_type = "DOWNSTREAM" if ecrcl_result["is_downstream"] else "UPSTREAM"
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

            # 7. 定位工件生成及物理归档
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

            # 🌟 核心拦截回调：判定当前项目的最终物理校验是否通过
            if verification_passed and final_suspect != "UNKNOWN":
                # 根因定位成功：写入 Success 并回填 commit 和 workspace 信息
                update_yaml_report(
                    file_path=self.config_yaml,
                    row_index=row_index,
                    result="Success",
                    commit=final_suspect,
                    workspace=attribution_type
                )
            else:
                # 根因定位失败/未通过反事实校验
                update_yaml_report(
                    file_path=self.config_yaml,
                    row_index=row_index,
                    result="Failure"
                )

        # 写入全局汇总 JSON
        consolidated_json_path = os.path.join(output_results_dir, "consolidated_results.json")
        with open(consolidated_json_path, 'w', encoding='utf-8') as j_f:
            json.dump(consolidated_results, j_f, indent=2, ensure_ascii=False)
        logger.info("All projects analyzed. Pipeline finished successfully.")


if __name__ == "__main__":
    pipeline = StandalonePipeline()
    pipeline.run_pipeline()
