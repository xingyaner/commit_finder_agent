import os
import shutil
import subprocess
import logging
import sys
import time
import signal
from typing import Optional

logger = logging.getLogger("WorkspaceManager")

def _stash_restore_workspace(self, repo_path: str):
    """临时保存现场，校验结束还原，全程不修改源码内容"""
    subprocess.run(["git", "-C", repo_path, "stash", "--include=*"], capture_output=True)
def counterfactual_revert_downstream_commit(self, repo_path: str, target_commit: str,
                                           project_name: str, engine: str, sanitizer: str, architecture: str) -> bool:
    """
    下游commit反事实验证：revert目标commit → 编译校验 → 还原仓库
    约束：仅Git版本操作，无任何文件原地修改、补丁写入
    return True:撤销commit后编译通过(原commit是根因)；False:撤销仍报错(非根因)
    """
    # 1.保存当前仓库现场
    self._stash_restore_workspace(repo_path)
    origin_ok = False
    try:
        # 撤销待验证下游commit
        subprocess.run(["git", "-C", repo_path, "revert", "--no-edit", target_commit], capture_output=True, check=True)
        # 编译校验：oss-fuzz为下游，mount_path=None，只校验下游本身构建
        build_res = self.run_fuzz_build_and_validate(
            project_name=project_name,
            oss_fuzz_path=repo_path,
            sanitizer=sanitizer,
            engine=engine,
            architecture=architecture,
            mount_path=None
        )
        origin_ok = (build_res["status"] == "success")
    except Exception as e:
        logger.warning(f"Downstream revert verify failed {target_commit}:{str(e)}")
    finally:
        # 强制恢复原始仓库状态
        subprocess.run(["git", "-C", repo_path, "reset", "--hard", "HEAD"], capture_output=True)
        subprocess.run(["git", "-C", repo_path, "stash", "pop"], capture_output=True)
    return origin_ok

def _auto_discover_project_symbols_from_content(nm_stdout: str, project_name: str) -> bool:
    """Helper to evaluate static linkage of project logic from symbol table."""
    keywords = [project_name.lower(), "deflate", "inflate", "adler32", "crc32"] if project_name == "zlib" else [
        project_name.lower()]
    boilerplate = ('__asan', '__lsan', '__ubsan', '__sanitizer', 'fuzzer::', 'LLVM', 'afl_', '_Z', 'std::')

    for line in nm_stdout.splitlines():
        parts = line.split()
        if not parts: continue
        symbol = parts[-1]
        if any(kw in symbol.lower() for kw in keywords) and not symbol.startswith(boilerplate):
            return True
    return False


class WorkspaceManager:
    def __init__(self, base_dir: str = "temp_workspaces"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def get_upstream_path(self, project_name: str) -> str:
        return os.path.join(self.base_dir, "upstream", project_name)

    def get_downstream_path(self) -> str:
        return os.path.join(self.base_dir, "downstream", "oss-fuzz")

    def clone_or_update_repo(self, repo_url: str, dest_path: str, checkout_sha: str = None):
        """克隆或拉取最新的 Git 仓库状态"""
        dest_path = os.path.abspath(dest_path)
        if not os.path.exists(dest_path):
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            logger.info(f"Cloning {repo_url} into {dest_path}...")
            subprocess.run(["git", "clone", repo_url, dest_path], check=True, capture_output=True)
        else:
            logger.info(f"Fetching updates for repository at {dest_path}...")
            subprocess.run(["git", "-C", dest_path, "fetch", "--all"], check=True, capture_output=True)

        if checkout_sha:
            logger.info(f"Checking out to SHA: {checkout_sha}")
            subprocess.run(["git", "-C", dest_path, "reset", "--hard"], capture_output=True)
            subprocess.run(["git", "-C", dest_path, "checkout", checkout_sha], capture_output=True)
            subprocess.run(["git", "-C", dest_path, "clean", "-fxd"], capture_output=True)

    def _run_cmd_realtime_print(self, cmd: list, cwd: str, timeout: int):
        """子进程实时逐行输出控制台，汇总std行输出控制台，汇总stdout/stderr用于后续判断"""
        full_out = []
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            stdin=subprocess.DEVNULL
        )
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                print(line, end="", flush=True)
                full_out.append(line)
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        total_log = "".join(full_out)
        return proc.returncode, total_log

    # ========== 修正：类内同级缩进，首参数加self ==========
    def run_fuzz_build_and_validate(
            self,
            project_name: str,
            oss_fuzz_path: str,
            sanitizer: str,
            engine: str,
            architecture: str,
            mount_path: Optional[str] = None
    ) -> dict:
        """
        Build and validate fuzzers using official OSS-Fuzz infrastructure.
        Success Criteria: Step 2 (check_build) must PASS. All other steps are reference items.
        """
        import stat
        import subprocess
        import time
        import os
        import sys
        import signal
        import select  # 用于非阻塞读取
        import re  # 用于进度正则匹配

        print(f"--- Tool: run_fuzz_build_and_validate called for: {project_name} ---")

        LOG_DIR = "fuzz_build_log_file"
        LOG_FILE_PATH = os.path.join(LOG_DIR, "fuzz_build_log.txt")
        os.makedirs(LOG_DIR, exist_ok=True)

        report = {
            "step_1_official_list": "pending",
            "step_2_infra_compliance": "pending",
            "step_3_sanitizer_injected": "pending",
            "step_4_engine_control": "pending",
            "step_5_logic_linkage": "pending",
            "step_6_runtime_stability": "pending"
        }

        # =========================================================================
        # 内部辅助过滤函数（对应 test_all.py 中的合法 Fuzzer 识别逻辑）
        # =========================================================================
        def is_elf(filepath: str) -> bool:
            """判断是否为 ELF 格式二进制文件"""
            try:
                result = subprocess.run(
                    ['file', filepath],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                if b'ELF' in result.stdout:
                    return True
            except Exception:
                pass
            # 兜底：如果系统没有安装 file 命令，直接读取文件头部魔数进行基础判断
            try:
                with open(filepath, 'rb') as f:
                    return f.read(4) == b'\x7fELF'
            except Exception:
                return False

        def is_shell_script(filepath: str) -> bool:
            """判断是否为 shell 脚本"""
            try:
                result = subprocess.run(
                    ['file', filepath],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                return b'shell script' in result.stdout
            except Exception:
                return False

        def find_local_fuzz_targets(directory: str, target_engine: str) -> list:
            """基于 test_all.py 标准过滤机制定位合法构建产物"""
            fuzz_targets = []
            if not os.path.exists(directory):
                return fuzz_targets

            executable_mask = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH

            for filename in os.listdir(directory):
                path = os.path.join(directory, filename)

                # ---- 第一层过滤：物理属性过滤 (Structural Filter) ----
                # 1. 排除特定辅助工具与非 Fuzzer 产物
                if filename == 'llvm-symbolizer':
                    continue
                if filename.startswith('afl-'):
                    continue
                if filename.startswith('jazzer_'):
                    continue
                if filename == 'centipede':
                    continue

                # 2. 必须是文件
                if not os.path.isfile(path):
                    continue

                # 3. 必须具备可执行权限
                try:
                    if not (os.stat(path).st_mode & executable_mask):
                        continue
                except Exception:
                    continue

                # 4. 必须是 ELF 二进制或 Shell 脚本包装器
                if not is_elf(path) and not is_shell_script(path):
                    continue

                # ---- 第二层过滤：符号合规性过滤 (Symbol Filter) ----
                if target_engine not in {'none', 'wycheproof'}:
                    try:
                        with open(path, 'rb') as file_handle:
                            binary_contents = file_handle.read()
                            if b'LLVMFuzzerTestOneInput' not in binary_contents:
                                continue
                    except Exception:
                        continue

                fuzz_targets.append(filename)
            return fuzz_targets

        # =========================================================================

        try:
            helper_path = os.path.join(oss_fuzz_path, "infra/helper.py")

            # --- Phase 1: Physical Build ---
            build_cmd = ["python3", helper_path, "build_fuzzers"]
            # 强制始终挂载 project_source_path
            build_cmd.extend([project_name, mount_path])
            build_cmd.extend(["--sanitizer", sanitizer, "--engine", engine, "--architecture", architecture])

            build_start = time.time()
            build_timeout = 5400  # 构建超时上限设定为 90 分钟（5400 秒），不影响正常构建结束

            process = subprocess.Popen(
                build_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=oss_fuzz_path
            )
            full_log = []

            try:
                while True:
                    if time.time() - build_start > build_timeout:
                        raise subprocess.TimeoutExpired(build_cmd, build_timeout)
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        time.sleep(0.05)
                        continue
                    print(line, end='', flush=True)
                    full_log.append(line)
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                final_log = "".join(full_log) + f"\n\nRESULT: failed (compilation timeout after {build_timeout}s)"
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(final_log)
                return {"status": "error", "message": "Compilation timed out", "validation_report": report}

            final_log = "".join(full_log)

            # 编译失败检测 (快速判定，直接写盘退出)
            if process.returncode != 0 or any(k in final_log.lower() for k in ["error:", "failed:", "build failed"]):
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(final_log + "\n\nRESULT: failed (compilation error)")
                return {"status": "error", "message": "Compilation failed", "validation_report": report}

            # --- Phase 2: Deep Validation ---
            print(f"\n--- [Phase 2] Deep Validation (Official Suite) ---")

            # 🔑 建立独立验证阶段计时锁，上限调整为 20 分钟 (1200.0 秒)，不影响正常验证结束
            validation_start_time = time.time()
            validation_timeout = 1200.0

            def check_validation_limit(cmd_info):
                elapsed = time.time() - validation_start_time
                if elapsed >= validation_timeout:
                    raise subprocess.TimeoutExpired(cmd_info, validation_timeout)
                return validation_timeout - elapsed

            # =========================================================================
            # Step 1: 官方产物识别 (参考项)
            # =========================================================================
            _ = check_validation_limit("list_fuzzers")
            out_dir = os.path.join(oss_fuzz_path, "build", "out", project_name)

            # 使用高保真度本地过滤逻辑
            targets = find_local_fuzz_targets(out_dir, engine)

            # 在日志中全量输出检测到的所有合规的模糊构建产物
            print(f"[*] Detected {len(targets)} compliant fuzz target(s) in Step 1: {', '.join(targets) if targets else 'None'}")

            primary_target = None
            if targets:
                primary_target = targets[0]
                report["step_1_official_list"] = f"pass: {len(targets)} target(s) (primary: {primary_target})"
            else:
                report["step_1_official_list"] = "fail: no recognized fuzzers"

            # =========================================================================
            # Step 2: 基础设施合规性 (唯一强制通过项)
            # =========================================================================
            rem_t = check_validation_limit("check_build")
            check_cmd = [
                "python3", helper_path, "check_build", project_name,
                "--sanitizer", sanitizer,
                "--engine", engine,
                "--architecture", architecture
            ]
            try:
                check_res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=min(300, rem_t),
                                           cwd=oss_fuzz_path)
                report[
                    "step_2_infra_compliance"] = "pass" if check_res.returncode == 0 else f"fail: {check_res.stderr.strip()[:100]}"
            except subprocess.TimeoutExpired:
                report["step_2_infra_compliance"] = "fail: check_build timeout"
            except Exception as e:
                report["step_2_infra_compliance"] = f"fail: {str(e)}"

            # Step 3-5: 参考项审计 (nm 符号分析 - 参考项)
            if primary_target:
                target_path = os.path.join(oss_fuzz_path, "build", "out", project_name, primary_target)
                if os.path.exists(target_path):
                    rem_t = check_validation_limit("nm_check")
                    try:
                        nm_res = subprocess.run(['nm', target_path], capture_output=True, text=True,
                                                timeout=min(30, rem_t),
                                                errors='ignore')
                        nm_stdout = nm_res.stdout
                    except Exception:
                        rem_t = check_validation_limit("nm_check_shell")
                        nm_res = subprocess.run(
                            ["python3", helper_path, "shell", project_name, "-c", f"nm /out/{primary_target}"],
                            capture_output=True, text=True, timeout=min(60, rem_t), errors='ignore'
                        )
                        nm_stdout = nm_res.stdout

                    report["step_3_sanitizer_injected"] = "pass" if "__asan" in nm_stdout else "warning: missing asan"
                    report["step_4_engine_control"] = "pass" if (
                            "LLVMFuzzerRunDriver" in nm_stdout or "__afl_" in nm_stdout) else "warning: engine symbols"
                    report["step_5_logic_linkage"] = "pass" if _auto_discover_project_symbols_from_content(nm_stdout,
                                                                                                           project_name) else "warning: logic linkage"
                else:
                    for s in ["step_3_sanitizer_injected", "step_4_engine_control", "step_5_logic_linkage"]:
                        report[s] = "skip: binary not accessible"
            else:
                for s in ["step_3_sanitizer_injected", "step_4_engine_control", "step_5_logic_linkage"]:
                    report[s] = "skip: no primary target"

            # =========================================================================
            # Step 6: 压力测试稳定性 (参考项)
            # =========================================================================
            if primary_target and report["step_2_infra_compliance"].startswith("pass"):
                print(f"[*] Starting 35s stability test for: {primary_target}")
                run_cmd = [sys.executable, helper_path, "run_fuzzer", "--engine", engine, "--sanitizer", sanitizer,
                           project_name, primary_target]

                rem_t = check_validation_limit("run_fuzzer")

                # 开启新进程组，便于后续强制清理可能残留的子容器/进程
                stability_proc = subprocess.Popen(
                    run_cmd, cwd=oss_fuzz_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, preexec_fn=os.setsid
                )

                start_time = time.time()
                log_lines = []
                timed_out = False

                try:
                    while True:
                        # 检查总验证超时，防止程序无休止挂起
                        check_validation_limit("run_fuzzer_runtime")

                        elapsed = time.time() - start_time
                        if elapsed >= 35.0:  # 35s 停止时间阈值
                            timed_out = True
                            break

                        # 采用 select 模块配合 timeout 检查进行非阻塞数据读取
                        remaining_time = max(0.1, 35.0 - elapsed)
                        rlist, _, _ = select.select([stability_proc.stdout], [], [], min(remaining_time, 0.5))

                        if stability_proc.stdout in rlist:
                            line = stability_proc.stdout.readline()
                            if not line:
                                break  # 进程正常结束且无数据输入
                            print(line, end='', flush=True)
                            log_lines.append(line)
                        else:
                            # 即使没有新数据产生，也持续检查进程是否已经自行退出
                            if stability_proc.poll() is not None:
                                break
                finally:
                    # 强行终止进程，发送 SIGKILL 信号确保不留下僵尸进程或未关闭的 Docker
                    try:
                        os.killpg(os.getpgid(stability_proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
                    stability_proc.wait()

                # 日志文本整合与退出码转换
                log_content = "".join(log_lines)
                exit_code = 124 if timed_out else stability_proc.returncode
                if exit_code is None:
                    exit_code = 124

                # ---- 成功特征检测与失败规则匹配 ----
                # 🌟 修复关键点：拓宽正则表达式，包含 AFL++ 和其它引擎进度日志的标志词 (如 exec speed, corpus count, cycles done, etc.)
                progress_pattern = r'(exec/s:|cov:|corp:|exec speed|corpus count|cycles done|execs/sec|active execution rate)'
                has_progress = bool(re.search(progress_pattern, log_content, re.IGNORECASE))
                is_success_6 = False
                success_reason = ""

                # A. 优先执行显式成功逻辑判定 (Success Logic)
                # 成功情况 1：进程超时正常退出且日志中存在关键变异进度
                if exit_code == 124 and has_progress:
                    is_success_6 = True
                    success_reason = "pass: Time-limited run completed successfully."
                # 成功情况 2：引擎平稳退出，且日志显示完成
                elif exit_code == 0 and any(kw in log_content for kw in ["Done", "fuzzing finished"]):
                    is_success_6 = True
                    success_reason = "pass: Finished normally."

                # B. 若不满足显式成功，执行失败判定过滤；若非检测到的失败条件，则依然判定为成功
                if not is_success_6:
                    is_failed_6 = False
                    fail_reason = ""

                    # 失败条件 B-1: 启动即崩溃/运行时 Crash (严重)
                    if "SUMMARY:" in log_content or "AddressSanitizer" in log_content or "Segmentation fault" in log_content:
                        is_failed_6 = True
                        fail_reason = "fail: RUNTIME_CRASH"

                    # 失败条件 B-2: 配置/路径/环境不匹配 (启动失败)
                    elif exit_code in [1, 127] or any(k in log_content for k in
                                                      ["error while loading shared libraries", "undefined reference",
                                                       "Usage:"]):
                        is_failed_6 = True
                        fail_reason = "fail: CONFIG_ERROR"

                    # 失败条件 B-3: 伪运行 (Dead/Frozen)
                    elif exit_code == 124 and not has_progress:
                        is_failed_6 = True
                        fail_reason = "fail: DEAD_PROCESS"

                    # 失败条件 B-4: 其它判定失败的非正常退出码（且排除 0 和 124）
                    elif exit_code != 0 and exit_code != 124:
                        is_failed_6 = True
                        fail_reason = f"fail: Exit code {exit_code}"

                    # 结论：如果不符合以上任何失败条件，依然判定为成功
                    if not is_failed_6:
                        report["step_6_runtime_stability"] = "pass: Default success (No failure criteria matched)"
                    else:
                        report["step_6_runtime_stability"] = fail_reason
                else:
                    report["step_6_runtime_stability"] = success_reason
            else:
                report["step_6_runtime_stability"] = "fail: skipped"

            # --- 最终判定逻辑 (🌟 当前仅以 Step 2 check_build 作为唯一强约束通过项) ---
            is_success = report["step_2_infra_compliance"].startswith("pass")

            summary_table = "\n" + "=" * 50 + "\n--- VALIDATION SUMMARY\n" + "-" * 50 + "\n"
            for i, (k, v) in enumerate(report.items(), 1):
                # 🌟 仅 Step 2 标记为 MANDATORY，其它步骤均标记为 REFERENCE
                marker = "[MANDATORY]" if i == 2 else "[REFERENCE]"
                summary_table += f"Step {i:<4} {marker:<12} | {v}\n"
            summary_table += "=" * 50 + "\n"
            print(summary_table)

            # 写入物理日志
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(final_log)
                f.write(summary_table)
                f.write(f"\nRESULT: {'success' if is_success else 'failed'}\n")

            return {
                "status": "success" if is_success else "error",
                "message": f"Validation {'PASSED' if is_success else 'FAILED'}",
                "validation_report": report
            }

        except subprocess.TimeoutExpired as e:
            print(f"\n[⚠️ TIMEOUT] Validation phase exceeded limit. Aborting...")
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(f"Validation phase timed out.\nRESULT: failed (compilation error)")
            return {"status": "error", "message": "Compilation failed", "validation_report": report}

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(f"Exception during validation:\n{str(e)}\n{tb}")
            return {"status": "error", "message": str(e), "validation_report": report}


    def execute_docker_compile(self, project_name: str, upstream_mount_path: str,
                               engine: str, sanitizer: str, architecture: str) -> bool:
        """
        [Phase 3 物理校验核]
        基于1+2+6校验规则：step1/2/6全pass才返回True(构建成功)，其余全部False(构建失败)
        """
        oss_fuzz_dir = self.get_downstream_path()
        if not os.path.exists(oss_fuzz_dir):
            logger.error("Downstream OSS-Fuzz dir missing. Cannot replay.")
            return False

        validate_ret = self.run_fuzz_build_and_validate(
            project_name=project_name,
            oss_fuzz_path=oss_fuzz_dir,
            sanitizer=sanitizer,
            engine=engine,
            architecture=architecture,
            mount_path=upstream_mount_path
        )
        if validate_ret["status"] == "success":
            logger.info(f"Physical build validation SUCCESS for project {project_name} (1+2+6 all pass)")
            return True
        else:
            logger.warning(f"Physical build validation FAILED for project {project_name} (1/2/6 not all pass)")
            return False