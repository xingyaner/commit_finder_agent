import os
import re
import json
import logging
from typing import Dict, List
from litellm import completion

logger = logging.getLogger("CognitiveAgent")


class CognitiveAgent:
    """
    负责调用大语言模型进行高阶语义归因，并格式化输出标准的 Causal Chain 简报。
    """

    def __init__(self, model_name: str = "deepseek/deepseek-v4-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("DEEPSEEK_API_KEY") or os.getenv("DPSEEK_API_KEY")
        if not self.api_key:
            logger.warning("Neither DEEPSEEK_API_KEY nor DPSEEK_API_KEY variable is set!")

    def _compact_for_log(self, value, max_chars: int = 4000) -> str:
        if isinstance(value, str):
            text = value
        else:
            text = json.dumps(value, ensure_ascii=False, indent=2)
        if len(text) > max_chars:
            return text[:max_chars] + "\n... [LLM debug output truncated] ..."
        return text

    def load_instruction(self, filepath: str) -> str:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load instruction file: {e}")
            return "You are an expert Code Detective and Root Cause Analyst."

    def extract_and_clean_json(self, raw_content: str) -> str:
        """
        物理健全性过滤器：
        从大模型返回的原始 Markdown 或纯文本内容中提取 JSON，
        并递归消除由大模型幻觉生成的含有重复嵌套后缀（如 _OLD_OLD）的异常脏键。
        """
        json_str = raw_content.strip()
        # 1. 尝试提取 Markdown 中的 ```json ... ``` 块
        match = re.search(r'```json\s*(.*?)\s*```', raw_content, re.DOTALL | re.IGNORECASE)
        if match:
            json_str = match.group(1).strip()
        else:
            # 2. 兜底提取最外层括弧 {}
            match_brace = re.search(r'(\{.*\})', raw_content, re.DOTALL)
            if match_brace:
                json_str = match_brace.group(1).strip()

        try:
            data = json.loads(json_str)

            # 3. 递归清洗字典键值
            def clean_dict(d):
                if not isinstance(d, dict):
                    return d
                cleaned = {}
                for k, v in d.items():
                    # 规则 1：剔除包含连环叠加后缀（如 _OLD_OLD、_NEW_NEW、_DIFF_DIFF）的键名
                    is_corrupted = False
                    for suffix in ["_OLD", "_NEW", "_DIFF"]:
                        if suffix + suffix in k:
                            is_corrupted = True
                            break

                    # 规则 2：若键名中包含这三种后缀的总累计次数超过 2 次，基本属于异常递归，需强制过滤
                    if not is_corrupted:
                        suffix_count = sum(k.count(s) for s in ["_OLD", "_NEW", "_DIFF"])
                        if suffix_count > 2:
                            is_corrupted = True

                    if is_corrupted:
                        continue  # 抛弃该冗余脏键

                    # 递归清理嵌套结构
                    if isinstance(v, dict):
                        cleaned[k] = clean_dict(v)
                    elif isinstance(v, list):
                        cleaned[k] = [clean_dict(item) if isinstance(item, dict) else item for item in v]
                    else:
                        cleaned[k] = v
                return cleaned

            cleaned_data = clean_dict(data)
            return json.dumps(cleaned_data, indent=2, ensure_ascii=False)

        except Exception as e:
            # 容错防线：如果大模型生成的内容由于网络等外部原因无法被解析，返回原始文本，避免系统奔溃
            logger.warning(f"Failed to parse or clean JSON output from LLM: {e}")
            return raw_content

    def _parse_json_object(self, raw_content: str) -> Dict:
        json_str = raw_content.strip()
        match = re.search(r'```json\s*(.*?)\s*```', raw_content, re.DOTALL | re.IGNORECASE)
        if match:
            json_str = match.group(1).strip()
        else:
            match_brace = re.search(r'(\{.*\})', raw_content, re.DOTALL)
            if match_brace:
                json_str = match_brace.group(1).strip()
        return json.loads(json_str)

    def _run_json_task(self, system_prompt: str, user_prompt: str, task_name: str = "LLM_JSON_TASK") -> Dict:
        response = completion(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            api_key=self.api_key,
            temperature=0.1,
            top_p=0.2
        )
        raw_content = response.choices[0].message.content
        logger.info(f"[{task_name}] Raw LLM response:\n{self._compact_for_log(raw_content)}")
        parsed = self._parse_json_object(raw_content)
        logger.info(f"[{task_name}] Parsed JSON:\n{self._compact_for_log(parsed)}")
        return parsed

    def infer_attribution_workspace(self, project_name: str, failure_region_text: str, top_1_file: str) -> Dict:
        """
        由 LLM 判断故障初始归属空间。该结果仅用于归因语义和失败兜底，不直接写回根因 SHA。
        """
        system_prompt = (
            "You are a build-failure attribution classifier. Return JSON only. "
            "Choose whether the failure is more likely caused by the upstream project source "
            "or downstream OSS-Fuzz packaging/build configuration."
        )
        user_prompt = f"""
Project: {project_name}
Observed related file: {top_1_file}

[FAILURE_REGION]
{failure_region_text}

Return exactly this JSON shape:
{{
  "attribution_type": "UPSTREAM or DOWNSTREAM",
  "confidence": "HIGH or LOW",
  "reason": "one concise sentence"
}}
"""
        try:
            result = self._run_json_task(system_prompt, user_prompt, task_name="ATTRIBUTION_WORKSPACE")
            attribution_type = str(result.get("attribution_type", "")).upper()
            if attribution_type not in {"UPSTREAM", "DOWNSTREAM"}:
                attribution_type = "UPSTREAM"
            confidence = str(result.get("confidence", "LOW")).upper()
            if confidence not in {"HIGH", "LOW"}:
                confidence = "LOW"
            return {
                "attribution_type": attribution_type,
                "confidence": confidence,
                "reason": str(result.get("reason", "")).strip()
            }
        except Exception as e:
            logger.error(f"LLM attribution inference failed: {e}")
            return {"attribution_type": "UPSTREAM", "confidence": "LOW", "reason": "LLM attribution failed."}

    def select_initial_suspects(
            self,
            project_name: str,
            failure_region_text: str,
            candidate_commits: List[Dict],
            max_count: int = 4
    ) -> List[str]:
        """
        第一阶段：LLM 读取时间窗口内所有候选 commit 简表，选出最多 4 个嫌疑 SHA。
        """
        allowed_shas = {c["sha"] for c in candidate_commits}
        logger.info(
            f"[INITIAL_SUSPECT_SELECTION] Candidate count: {len(candidate_commits)}; "
            f"allowed SHAs: {sorted(allowed_shas)}"
        )
        compact_candidates = []
        for c in candidate_commits:
            compact_candidates.append({
                "sha": c.get("sha"),
                "origin": c.get("origin"),
                "date": c.get("date"),
                "author": c.get("author"),
                "title": c.get("message"),
                "changed_files": c.get("changed_files", [])[:20],
                "selection_source": c.get("selection_source")
            })

        system_prompt = (
            "You are a fuzzing build-failure root-cause commit selector. Return JSON only. "
            "Select only SHA values that are present in the provided candidate list. "
            "Do not invent commits."
        )
        user_prompt = f"""
Project: {project_name}

[FAILURE_REGION]
{failure_region_text}

[CANDIDATE_COMMITS_BRIEF_JSON]
{json.dumps(compact_candidates, ensure_ascii=False, indent=2)}

Choose the {max_count} commits most likely to have caused this fuzzing build failure.
Prefer commits whose title or changed files can physically explain compiler, linker,
dependency, toolchain, Docker, OSS-Fuzz packaging, or source API failures.

Return exactly this JSON shape:
{{
  "selected_shas": ["sha1", "sha2", "sha3", "sha4"],
  "reason": "one concise sentence"
}}
"""
        try:
            result = self._run_json_task(system_prompt, user_prompt, task_name="INITIAL_SUSPECT_SELECTION")
            selected = result.get("selected_shas", [])
            if not isinstance(selected, list):
                logger.warning(
                    f"[INITIAL_SUSPECT_SELECTION] selected_shas is not a list: "
                    f"{self._compact_for_log(selected, max_chars=1000)}"
                )
                selected = []
            logger.info(f"[INITIAL_SUSPECT_SELECTION] LLM selected before filtering: {selected}")
            filtered = []
            for sha in selected:
                sha = str(sha).strip()
                if sha in allowed_shas and sha not in filtered:
                    filtered.append(sha)
                elif sha not in allowed_shas:
                    logger.warning(f"[INITIAL_SUSPECT_SELECTION] Dropping non-candidate SHA from LLM output: {sha}")
                elif sha in filtered:
                    logger.warning(f"[INITIAL_SUSPECT_SELECTION] Dropping duplicate SHA from LLM output: {sha}")
                if len(filtered) >= max_count:
                    break
            if not filtered and candidate_commits:
                # Preserve the complete attribution-filtered pool for the final
                # selector.  The initial selector is only a narrowing stage;
                # an empty answer here must not silently decide the SHA by list
                # position and deprive the final LLM of the remaining evidence.
                filtered = [str(candidate["sha"]).strip() for candidate in candidate_commits]
                logger.warning(
                    "[INITIAL_SUSPECT_SELECTION] LLM returned no usable SHA; "
                    f"passing all {len(filtered)} attribution-filtered candidates "
                    "to final selection"
                )
            logger.info(f"[INITIAL_SUSPECT_SELECTION] Filtered selected SHAs: {filtered}")
            return filtered
        except Exception as e:
            logger.error(f"LLM initial suspect selection failed: {e}")
            if candidate_commits:
                fallback_shas = [str(candidate["sha"]).strip() for candidate in candidate_commits]
                logger.warning(
                    "[INITIAL_SUSPECT_SELECTION] LLM failed; "
                    f"passing all {len(fallback_shas)} attribution-filtered candidates "
                    "to final selection"
                )
                return fallback_shas
            return []

    def select_final_suspects(
            self,
            project_name: str,
            failure_region_text: str,
            detailed_candidates: List[Dict],
            max_count: int = 2
    ) -> List[str]:
        """
        第二阶段：LLM 读取最多 4 个候选的详细信息，选出最多 2 个用于反事实验证。
        """
        allowed_shas = {c["sha"] for c in detailed_candidates}
        logger.info(
            f"[FINAL_SUSPECT_SELECTION] Detailed candidate count: {len(detailed_candidates)}; "
            f"allowed SHAs: {sorted(allowed_shas)}"
        )
        if not detailed_candidates:
            logger.error("[FINAL_SUSPECT_SELECTION] No detailed candidates were provided to the LLM.")
        system_prompt = (
            "You are a fuzzing build-failure root-cause commit selector. Return JSON only. "
            "Select only SHA values that are present in the detailed candidate list. "
            "These selected commits will be physically replayed; do not invent commits."
        )
        user_prompt = f"""
Project: {project_name}

[FAILURE_REGION]
{failure_region_text}

[DETAILED_CANDIDATE_COMMITS_JSON]
{json.dumps(detailed_candidates, ensure_ascii=False, indent=2)}

Choose the {max_count} commits most likely to have caused this exact fuzzing build failure.
Use the detailed diff/stat context to determine whether the commit can physically explain
the failure. The selected commits will still need counterfactual verification.

Return exactly this JSON shape:
{{
  "selected_shas": ["sha1", "sha2"],
  "reason": "one concise sentence"
}}
"""
        try:
            result = self._run_json_task(system_prompt, user_prompt, task_name="FINAL_SUSPECT_SELECTION")
            selected = result.get("selected_shas", [])
            if not isinstance(selected, list):
                logger.warning(
                    f"[FINAL_SUSPECT_SELECTION] selected_shas is not a list: "
                    f"{self._compact_for_log(selected, max_chars=1000)}"
                )
                selected = []
            logger.info(f"[FINAL_SUSPECT_SELECTION] LLM selected before filtering: {selected}")
            filtered = []
            for sha in selected:
                sha = str(sha).strip()
                if sha in allowed_shas and sha not in filtered:
                    filtered.append(sha)
                elif sha not in allowed_shas:
                    logger.warning(f"[FINAL_SUSPECT_SELECTION] Dropping non-candidate SHA from LLM output: {sha}")
                elif sha in filtered:
                    logger.warning(f"[FINAL_SUSPECT_SELECTION] Dropping duplicate SHA from LLM output: {sha}")
                if len(filtered) >= max_count:
                    break
            if not filtered:
                logger.error(
                    "[FINAL_SUSPECT_SELECTION] No valid SHAs remained after filtering. "
                    "Check raw LLM response and allowed SHA list above."
                )
                if detailed_candidates:
                    filtered = [str(detailed_candidates[0]["sha"]).strip()]
                    logger.warning(
                        "[FINAL_SUSPECT_SELECTION] LLM returned no usable SHA; "
                        f"falling back to candidate {filtered[0]} for physical replay"
                    )
            logger.info(f"[FINAL_SUSPECT_SELECTION] Filtered selected SHAs: {filtered}")
            return filtered
        except Exception as e:
            logger.error(f"LLM final suspect selection failed: {e}")
            if detailed_candidates:
                fallback_sha = str(detailed_candidates[0]["sha"]).strip()
                logger.warning(
                    "[FINAL_SUSPECT_SELECTION] LLM failed; "
                    f"falling back to candidate {fallback_sha} for physical replay"
                )
                return [fallback_sha]
            return []

    def execute_arbitration(self, context_data: dict, instruction_path: str) -> str:
        """
        利用 LiteLLM 驱动 Agent 将物理图算法势能和重放事实转化为可读报告。
        支持对“根因定位失败”进行高亮标注。
        """
        instruction = self.load_instruction(instruction_path)

        user_prompt = f"""
        We have completed the physical graph-based ECRCL analysis with ten sequential
        attempts. Here is the highly distilled context package:

        [FAILURE_LOG_CONTEXT]
        {context_data.get('failure_region_text')}

        [IDENTIFIED_ROOT_COMMIT]
        SHA: {context_data.get('final_suspect')}
        Author: {context_data.get('target_author')}
        Date: {context_data.get('target_date')}
        Title: {context_data.get('target_title')}
        Confidence: {context_data.get('confidence')}
        Workspace: {context_data.get('attribution_type')}
        Target File: {context_data.get('top_1_file')}
        Target Line: {context_data.get('line_num')}
        Code Before: {context_data.get('before_line')}
        Code After: {context_data.get('after_line')}

        [DIFF_CONTEXT]
        {context_data.get('diff_text')}

        [COUNTERFACTUAL_REPLAY_RESULT]
        Status: {context_data.get('validation_status')}

        Analyze this context and write a complete report matching the requested schema exactly.
        CRITICAL RULE: If the SHA is 'UNKNOWN', you MUST explicitly mark that
        root cause localization failed ("根因定位失败") in your FINAL_ATTRIBUTION and
        CAUSAL_CHAIN, noting that all top 10 candidate commits failed counterfactual
        replay. 
        """
        try:
            response = completion(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": instruction},
                    {"role": "user", "content": user_prompt}
                ],
                api_key=self.api_key,
                temperature=0.2,
                top_p=0.3
            )
            raw_content = response.choices[0].message.content
            # 对大模型输出的文本执行物理键名过滤清洗
            return self.extract_and_clean_json(raw_content)
        except Exception as e:
            logger.error(f"LiteLLM call failed: {e}")
            return f"Error: LLM arbitration failed due to {str(e)}"
