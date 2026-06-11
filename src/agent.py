import os
import re
import json
import logging
from litellm import completion

logger = logging.getLogger("CognitiveAgent")


class CognitiveAgent:
    """
    负责调用大语言模型进行高阶语义归因，并格式化输出标准的 Causal Chain 简报。
    """

    def __init__(self, model_name: str = "deepseek/deepseek-chat"):
        self.model_name = model_name
        self.api_key = os.getenv("DEEPSEEK_API_KEY") or os.getenv("DPSEEK_API_KEY")
        if not self.api_key:
            logger.warning("Neither DEEPSEEK_API_KEY nor DPSEEK_API_KEY variable is set!")

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

    def execute_arbitration(self, context_data: dict, instruction_path: str) -> str:
        """
        利用 LiteLLM 驱动 Agent 将物理图算法势能和重放事实转化为可读报告。
        支持对“根因定位失败”进行高亮标注。
        """
        instruction = self.load_instruction(instruction_path)

        user_prompt = f"""
We have completed the physical graph-based ECRCL analysis with six sequential
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
CAUSAL_CHAIN, noting that all top 6 candidate commits failed counterfactual
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