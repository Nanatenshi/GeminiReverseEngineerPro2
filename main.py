# ==============================================================================
# Gemini Reverse Engineering Assistant Pro for Ghidra
# @category AI Analysis
# @author Security Research & Reverse Engineering
# @menupath Analysis.Gemini.Launch Gemini Assistant Pro
# @toolbar icon.png
# ==============================================================================

import os
import sys
import json
import re
import time
from datetime import datetime
from pathlib import Path

# --- Google GenAI SDK ---
try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[!] エラー: 'google-genai' SDK が見つかりません。")
    print("    ターミナルで 'pip install google-genai' を実行してください。")
    raise

# --- Ghidra API ---
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit, Function
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

CONFIG_FILE_PATH = Path.home() / ".ghidra_gemini_config.json"

# ==============================================================================
# 1. 設定マネージャ (API Key・Model の永続化)
# ==============================================================================
class ConfigManager:
    @staticmethod
    def load_config():
        if CONFIG_FILE_PATH.exists():
            try:
                with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    @staticmethod
    def save_config(config):
        try:
            with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"[!] 設定の保存に失敗しました: {e}")

    @classmethod
    def get_api_key(cls):
        # 1. 環境変数を優先
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            return api_key
        
        # 2. 設定ファイルを確認
        config = cls.load_config()
        if "api_key" in config and config["api_key"]:
            return config["api_key"]
        
        # 3. GUIダイアログでユーザーに入力を要求
        api_key = askString("Gemini API Key Required", "Google AI StudioのAPIキーを入力してください:")
        if api_key:
            config["api_key"] = api_key.strip()
            cls.save_config(config)
            return config["api_key"]
        return None

    @classmethod
    def get_model_name(cls):
        config = cls.load_config()
        return config.get("model_name", "gemini-2.5-flash")


# ==============================================================================
# 2. デコンパイラヘルパー
# ==============================================================================
class GhidraDecompilerHelper:
    def __init__(self, program):
        self.program = program
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(self.program)

    def decompile(self, function, timeout_sec=45):
        monitor = ConsoleTaskMonitor()
        res = self.decompiler.decompileFunction(function, timeout_sec, monitor)
        if res and res.decompileCompleted():
            decomp_func = res.getDecompiledFunction()
            if decomp_func:
                return decomp_func.getC()
        return None

    def close(self):
        self.decompiler.dispose()


# ==============================================================================
# 3. プロンプト & 解析エンジン
# ==============================================================================
class GeminiReverseEngine:
    def __init__(self, api_key: str, model_id: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = model_id

    def call_gemini(self, system_instruction: str, prompt: str, temperature: float = 0.2) -> str:
        response = self.client.models.generate_content(
            model=self.model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=temperature
            )
        )
        return response.text

    def analyze_function(self, func_name: str, c_code: str) -> str:
        system_instruction = """
あなたは最高峰のリバースエンジニアリング専門家です。
GhidraによってデコンパイルされたCコードを分析し、開発者の意図やアルゴリズムを明確に解明してください。

【出力フォーマット】
### 1. 関数の概要と主要機能
### 2. 引数および戻り値の解説 (推測される型と役割)
### 3. アルゴリズム・内部ロジックの詳細ステップ
### 4. 特筆すべき挙動 / 外部API・システムコール呼び出し
"""
        prompt = f"関数名: `{func_name}`\n\n```c\n{c_code}\n```"
        return self.call_gemini(system_instruction, prompt)

    def suggest_rename(self, func_name: str, c_code: str) -> dict:
        system_instruction = """
あなたはC言語リバースエンジニアリングにおける命名規則のスペシャリストです。
提供されたデコンパイルコードの処理内容を精査し、最も適切で自己説明的な関数名および主要変数のリネーム案を提案してください。
出力は必ず純粋なJSONフォーマットのみで行ってください。

【出力JSONスキーマ】
{
  "suggested_function_name": "例: parse_http_header / decrypt_payload",
  "confidence": "HIGH | MEDIUM | LOW",
  "reason": "命名理由の簡潔な解説",
  "suggested_variables": [
    {"original": "uVar1", "suggested": "buffer_length", "reason": "サイズ計算に使用"}
  ]
}
"""
        prompt = f"現在の関数名: `{func_name}`\n\n```c\n{c_code}\n```"
        raw_text = self.call_gemini(system_instruction, prompt, temperature=0.1)
        
        # JSONブロックの抽出
        match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', raw_text)
        json_str = match.group(1) if match else raw_text
        try:
            return json.loads(json_str)
        except Exception:
            return {"suggested_function_name": func_name, "reason": raw_text, "suggested_variables": []}

    def audit_security(self, func_name: str, c_code: str) -> str:
        system_instruction = """
あなたはセキュアコードレビューおよび脆弱性監査のスペシャリストです。
提供されたデコンパイルCコードから、潜在的な不具合、メモリ破損、境界値エラー、暗号誤用、入力検証不備などを特定してください。

【出力フォーマット】
### 1. 総合セキュリティ評価 (CRITICAL / HIGH / MEDIUM / LOW / SAFE)
### 2. 検出された潜在的リスク・脆弱性箇所 (行/構文ベースの指摘)
### 3. リスクの根本原因と想定影響
### 4. セキュアな修正方針 (C言語コード修正の指針)
"""
        prompt = f"関数名: `{func_name}`\n\n```c\n{c_code}\n```"
        return self.call_gemini(system_instruction, prompt, temperature=0.2)

    def recover_structures(self, func_name: str, c_code: str) -> str:
        system_instruction = """
あなたは低レイヤデータ構造の復元に長けたリバースエンジニアです。
デコンパイル結果内のポインタ演算（*(int *)(param_1 + 0x18) など）やアライメントを解析し、
背後にあるC言語の `struct` 定義を復元してください。

【出力フォーマット】
### 1. 推測される構造体定義 (C言語形式 typedef struct)
### 2. 各フィールドのオフセットおよび役割の解説
### 3. Ghidra Structure Editor への登録アドバイス
"""
        prompt = f"対象関数: `{func_name}`\n\n```c\n{c_code}\n```"
        return self.call_gemini(system_instruction, prompt, temperature=0.1)


# ==============================================================================
# 4. メインコントローラ
# ==============================================================================
def run_interactive_assistant():
    print("========================================================================")
    print(" [Gemini Reverse Engineering Assistant Pro] 起動")
    print("========================================================================")

    # 1. APIキー取得
    api_key = ConfigManager.get_api_key()
    if not api_key:
        popup("APIキーが提供されなかったため、処理を中断します。")
        return

    model_id = ConfigManager.get_model_name()
    engine = GeminiReverseEngine(api_key, model_id)
    decompiler_helper = GhidraDecompilerHelper(currentProgram)

    # 2. 現在の関数判定
    current_func = getFunctionContaining(currentAddress)

    # 3. 動作モードの選択
    modes = [
        "1. [単体] 詳細解説 & ロジック分析 (Overview & Logic)",
        "2. [単体] 自動リネーム提案 & 反映 (Smart Rename & Symbol Update)",
        "3. [単体] セキュリティ脆弱性・バグ監査 (Security & Vulnerability Audit)",
        "4. [単体] 構造体・データ型復元アシスト (Struct / Type Recovery)",
        "5. [一括] 未解析関数 (FUN_*) バッチ解析レポート出力 (Batch Markdown Report)"
    ]
    
    choice = askChoice("Gemini Analysis Pro", "実行する解析モードを選択してください:", modes, modes[0])
    if not choice:
        return

    try:
        # ----------------------------------------------------------------------
        # MODE 1: 詳細解説
        # ----------------------------------------------------------------------
        if choice.startswith("1."):
            if not current_func:
                popup("カーソルを対象の関数内に置いて実行してください。")
                return
            
            c_code = decompiler_helper.decompile(current_func)
            if not c_code:
                popup("関数のデコンパイルに失敗しました。")
                return

            println(f"[*] 解析中: {current_func.getName()}...")
            result = engine.analyze_function(current_func.getName(), c_code)
            
            # コメント適用
            apply_plate_comment(current_func, "Gemini Logic Analysis", result)
            createBookmark(current_func.getEntryPoint(), "Gemini_Analysis", "Logic Explained")
            println("\n" + result)
            popup(f"関数 '{current_func.getName()}' の解説をPlate Commentに反映しました。")

        # ----------------------------------------------------------------------
        # MODE 2: 自動リネーム
        # ----------------------------------------------------------------------
        elif choice.startswith("2."):
            if not current_func:
                popup("カーソルを対象の関数内に置いて実行してください。")
                return
            
            c_code = decompiler_helper.decompile(current_func)
            if not c_code:
                popup("関数のデコンパイルに失敗しました。")
                return

            println(f"[*] リネーム推論中: {current_func.getName()}...")
            rename_data = engine.suggest_rename(current_func.getName(), c_code)
            
            sug_name = rename_data.get("suggested_function_name", current_func.getName())
            reason = rename_data.get("reason", "")
            vars_list = rename_data.get("suggested_variables", [])
            
            msg = (f"【現在の名前】: {current_func.getName()}\n"
                   f"【提案された名前】: {sug_name}\n\n"
                   f"【理由】: {reason}\n\n"
                   f"関数名を '{sug_name}' に変更しますか？")
            
            if askYesNo("関数リネームの確認", msg):
                current_func.setName(sug_name, SourceType.USER_DEFINED)
                comment = f"Gemini Auto-Rename\nOriginal: {current_func.getName()}\nReason: {reason}"
                apply_plate_comment(current_func, "Gemini Rename Info", comment)
                println(f"[+] 関数名を '{sug_name}' に変更しました。")

        # ----------------------------------------------------------------------
        # MODE 3: セキュリティ監査
        # ----------------------------------------------------------------------
        elif choice.startswith("3."):
            if not current_func:
                popup("カーソルを対象の関数内に置いて実行してください。")
                return
            
            c_code = decompiler_helper.decompile(current_func)
            if not c_code:
                popup("関数のデコンパイルに失敗しました。")
                return

            println(f"[*] セキュリティ監査中: {current_func.getName()}...")
            audit_result = engine.audit_security(current_func.getName(), c_code)
            
            apply_plate_comment(current_func, "Gemini Security Audit", audit_result)
            createBookmark(current_func.getEntryPoint(), "Gemini_Security", "Audit Completed")
            println("\n" + audit_result)
            popup(f"関数 '{current_func.getName()}' の監査結果をPlate Commentに記録しました。")

        # ----------------------------------------------------------------------
        # MODE 4: 構造体・型復元
        # ----------------------------------------------------------------------
        elif choice.startswith("4."):
            if not current_func:
                popup("カーソルを対象の関数内に置いて実行してください。")
                return
            
            c_code = decompiler_helper.decompile(current_func)
            if not c_code:
                popup("関数のデコンパイルに失敗しました。")
                return

            println(f"[*] 構造体解析中: {current_func.getName()}...")
            struct_result = engine.recover_structures(current_func.getName(), c_code)
            
            apply_plate_comment(current_func, "Gemini Struct Recovery", struct_result)
            println("\n" + struct_result)
            popup("構造体推論結果をコンソールおよびPlate Commentに出力しました。")

        # ----------------------------------------------------------------------
        # MODE 5: 一括バッチ解析
        # ----------------------------------------------------------------------
        elif choice.startswith("5."):
            run_batch_analysis(engine, decompiler_helper)

    finally:
        decompiler_helper.close()


def apply_plate_comment(func: Function, title: str, content: str):
    entry_addr = func.getEntryPoint()
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(entry_addr)
    if code_unit:
        border = "=" * 60 + "\n"
        new_comment = f"{border} [ {title} ]\n{border}{content.strip()}\n{border}"
        existing = code_unit.getComment(CodeUnit.PLATE_COMMENT)
        if existing:
            new_comment = existing + "\n\n" + new_comment
        code_unit.setComment(CodeUnit.PLATE_COMMENT, new_comment)


def run_batch_analysis(engine: GeminiReverseEngine, decompiler_helper: GhidraDecompilerHelper):
    fm = currentProgram.getFunctionManager()
    funcs = [f for f in fm.getFunctions(True) if f.getName().startswith("FUN_")]
    
    if not funcs:
        popup("バッチ解析対象となる未命名関数 ('FUN_*') が見つかりませんでした。")
        return

    limit_str = askString("Batch Limit", f"解析する最大関数数を入力してください (全 {len(funcs)} 件中):", "10")
    try:
        limit = min(int(limit_str), len(funcs))
    except ValueError:
        limit = 10

    report_lines = [
        f"# 🛡️ Gemini Batch Reverse Engineering Report",
        f"- **ターゲットバイナリ:** `{currentProgram.getName()}`",
        f"- **実施日時:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **解析対象数:** {limit} 件\n",
        "---",
    ]

    monitor.initialize(limit)
    monitor.setMessage("Gemini Batch Analysis Progress...")

    for i, func in enumerate(funcs[:limit]):
        if monitor.isCancelled():
            break
        
        monitor.setProgress(i + 1)
        monitor.setMessage(f"解析中 ({i+1}/{limit}): {func.getName()}")
        
        c_code = decompiler_helper.decompile(func)
        if not c_code:
            continue

        rename_data = engine.suggest_rename(func.getName(), c_code)
        sug_name = rename_data.get("suggested_function_name", func.getName())
        reason = rename_data.get("reason", "N/A")

        report_lines.append(f"## {i+1}. `{func.getName()}` -> 推奨: `{sug_name}` (アドレス: `0x{func.getEntryPoint()}`)")
        report_lines.append(f"- **推奨命名理由:** {reason}")
        report_lines.append(f"- **コード抜粋:**\n```c\n{c_code[:300]}...\n```\n")

        # 自動でPlate Commentも更新
        apply_plate_comment(func, "Gemini Batch Triage", f"Suggested Name: {sug_name}\nReason: {reason}")
        time.sleep(0.5) # レートリミット対策

    # レポートファイルの保存
    report_path = Path.home() / f"{currentProgram.getName()}_Gemini_BatchReport.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    println(f"[+] バッチ解析が完了しました。レポート: {report_path}")
    popup(f"バッチ解析が完了しました！\n出力先: {report_path}")


# ==============================================================================
# エントリポイント
# ==============================================================================
if __name__ == "__main__":
    run_interactive_assistant()
