import argparse
from pathlib import Path

from .chunker import chunk_whole_file
from .agent import SmartContractVulnAgent

def load_categories(path: str):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", required=True, help="Path to .sol file")
    ap.add_argument("--model", default="deepseek-r1:7b")
    ap.add_argument("--out", default="outputs/results.json")
    args = ap.parse_args()

    sol_text = Path(args.contract).read_text(encoding="utf-8")
    chunk = chunk_whole_file(sol_text)

    owasp_categories = load_categories("config/owasp_2023_categories.txt") 

    agent = SmartContractVulnAgent(
        model=args.model,
        prompt_path="prompts/detect_vuln_prompt.txt",
        owasp_categories=owasp_categories
    )

    result = agent.analyze(chunk.code_with_lines)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.model_dump_json(indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()