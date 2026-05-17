# 🔐 Smart Contract Vulnerability Agent

> **Day la project cua INSECLAB**

An automated smart contract vulnerability auditing system powered by local LLM (Ollama + DeepSeek-R1). Analyzes Solidity contracts against OWASP 2023 Smart Contract Top 10 categories and generates structured vulnerability reports.

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Usage Guide](#usage-guide)
  - [1. run.py — SmartBugs Dataset Audit](#1-runpy--smartbugs-dataset-audit)
  - [2. runzeusvul.py — Zeus Contracts Audit](#2-runzeusvulpy--zeus-contracts-audit)
  - [3. python -m app — General Contract Audit](#3-python--m-app--general-contract-audit)
  - [4. generate_vul_report.py — Standalone Report Generator](#4-generate_vul_reportpy--standalone-report-generator)
- [Configuration](#configuration)
- [Output Format](#output-format)
- [Core Modules Reference](#core-modules-reference)
- [OWASP Vulnerability Categories](#owasp-vulnerability-categories)

---

## Prerequisites

- **Python 3.10+** with a virtual environment
- **Ollama** installed and running locally
- **DeepSeek-R1:7b** model pulled (`ollama pull deepseek-r1:7b`)

```bash
# Activate virtual environment
venv\Scripts\Activate       # Windows
source venv/bin/activate    # Linux/Mac

# Verify Ollama is running
ollama ps
```

---

## Quick Start

```bash
# 1. Activate venv
venv\Scripts\Activate

# 2. Run audit on SmartBugs dataset (auto-generates reports)
python run.py

# 3. Or run audit on Zeus contracts
python runzeusvul.py

# 4. Or audit custom contracts
python -m app --contracts-dir contracts
```

---

## Project Structure

```
contract-vul-agent/
│
├── run.py                          # Main runner: SmartBugs dataset audit
├── runzeusvul.py                   # Zeus vulnerable contracts audit
├── generate_vul_report.py          # Standalone report generator
│
├── app/                            # Core application package
│   ├── __init__.py
│   ├── agent.py                    # SmartContractVulnAgent orchestrator
│   ├── llm_client.py               # Ollama LLM client with retry logic
│   ├── chunker.py                  # Solidity code pre-processing
│   ├── json_extract.py             # Robust JSON extraction from LLM output
│   ├── schemas.py                  # Pydantic models for vulnerability data
│   └── main.py                     # CLI entry point (python -m app)
│
├── config/
│   └── owasp_2023_categories.txt   # OWASP vulnerability categories
│
├── prompts/
│   └── detect_vuln_prompt.txt      # LLM system prompt template
│
├── contracts/                      # Custom contracts for analysis (77 files)
├── smartbugs_dataset/              # SmartBugs benchmark dataset
│   ├── access_control/
│   ├── arithmetic/
│   ├── bad_randomness/
│   ├── denial_of_service/
│   ├── front_running/
│   ├── other/
│   ├── reentrancy/
│   ├── short_addresses/
│   ├── time_manipulation/
│   └── unchecked_low_level_calls/
│
├── LOGs/                           # Output directory for run.py
│   └── my_results/
│       ├── <folder>/               # Per-category results
│       │   ├── result_<name>.json
│       │   ├── audit_summary.json
│       │   ├── vulnerability_report.md
│       │   └── vulnerability_report.csv
│       ├── overall_audit_summary.json
│       ├── vulnerability_report.md
│       └── vulnerability_report.csv
│
└── zeus_results/                   # Output directory for runzeusvul.py
    ├── result_<name>.json
    ├── audit_summary.json
    ├── zeus_vulnerability_report.md
    └── zeus_vulnerability_report.csv
```

---

## Usage Guide

### 1. `run.py` — SmartBugs Dataset Audit

Audits all Solidity contracts across **all category sub-folders** in `smartbugs_dataset/`. Automatically generates vulnerability reports (MD + CSV) after the audit completes.

#### Run Full Audit

```bash
python run.py
```

#### Available Options

| Flag | Default | Description |
|------|---------|-------------|
| `--dataset-dir` | `smartbugs_dataset` | Root directory with category sub-folders |
| `--config` | `config/owasp_2023_categories.txt` | OWASP categories config file |
| `--prompt` | `prompts/detect_vuln_prompt.txt` | LLM system prompt template |
| `--model` | `deepseek-r1:7b` | Ollama model to use |
| `--output-dir` | `LOGs/my_results` | Base directory for results |
| `--max-files` | all | Limit files per folder |
| `--contract-file` | — | Analyze a specific `.sol` file. Can be repeated or comma-separated |
| `--file-range` | — | Analyze a 1-based inclusive range from the sorted contract index |
| `--list-contracts` | — | Print the indexed contract list used by `--file-range` |
| `--report` | — | Generate report only (no analysis) |

#### Examples

```bash
# Audit with a different model
python run.py --model llama3:8b

# Limit to 5 contracts per folder
python run.py --max-files 5

# Show the sorted contract index for range selection
python run.py --list-contracts

# Audit a specific contract by path relative to smartbugs_dataset/
python run.py --contract-file access_control/FibonacciBalance.sol

# Audit multiple specific contracts
python run.py --contract-file access_control/FibonacciBalance.sol --contract-file arithmetic/token.sol

# Audit contracts 5 through 10 from the --list-contracts index
python run.py --file-range 5:10

# Audit from the first contract through contract 10
python run.py --file-range :10

# Audit from contract 10 through the last contract
python run.py --file-range 10:

# Combine explicit files and ranges
python run.py --contract-file access_control/FibonacciBalance.sol --file-range 20:22

# Generate reports from existing results (no re-analysis)
python run.py --report

# Generate reports from a specific output directory
python run.py --report --output-dir LOGs/my_results
```

`--file-range` accepts `5`, `5:10`, `5-10`, `:10`, and `10:`. The indexes are 1-based and inclusive.

#### Output Structure

```
LOGs/my_results/
├── access_control/
│   ├── result_arbitrary_location_write_simple.json
│   ├── result_mapping_write.json
│   ├── ...
│   ├── audit_summary.json
│   ├── vulnerability_report.md        ← per-folder report
│   └── vulnerability_report.csv
├── reentrancy/
│   └── ...
├── overall_audit_summary.json
├── vulnerability_report.md            ← overall report
└── vulnerability_report.csv
```

---

### 2. `runzeusvul.py` — Zeus Contracts Audit

Audits contracts in `zeus_vulnerable_contracts/` with **concurrency**, **resume support** (skip already-processed), and **progress tracking with ETA**.

#### Run Full Audit

```bash
python runzeusvul.py
```

#### Available Options

| Flag | Default | Description |
|------|---------|-------------|
| `--contracts-dir` | `zeus_vulnerable_contracts` | Directory with `.sol` files |
| `--config` | `config/owasp_2023_categories.txt` | OWASP categories config file |
| `--prompt` | `prompts/detect_vuln_prompt.txt` | LLM system prompt template |
| `--model` | `deepseek-r1:7b` | Ollama model to use |
| `--output-dir` | `zeus_results` | Directory for results |
| `--max-files` | all | Limit number of files |
| `--workers` | `1` | Parallel workers (1 = sequential) |
| `--no-skip` | — | Re-analyze even if results exist |
| `--report` | — | Generate report only (no analysis) |

#### Examples

```bash
# Parallel audit with 4 workers
python runzeusvul.py --workers 4

# Resume interrupted run (skips already-processed)
python runzeusvul.py

# Force re-analysis of all contracts
python runzeusvul.py --no-skip

# Only generate report from existing results
python runzeusvul.py --report

# Audit with max 10 contracts
python runzeusvul.py --max-files 10

# Audit custom directory, save to custom output
python runzeusvul.py --contracts-dir my_contracts --output-dir my_output
```

---

### 3. `python -m app` — General Contract Audit

A simpler auditing CLI for analyzing any directory of `.sol` files.

```bash
python -m app
```

#### Available Options

| Flag | Default | Description |
|------|---------|-------------|
| `--contracts-dir` | `contracts` | Directory with `.sol` files |
| `--config` | `config/owasp_2023_categories.txt` | OWASP categories config file |
| `--prompt` | `prompts/detect_vuln_prompt.txt` | LLM system prompt template |
| `--model` | `deepseek-r1:7b` | Ollama model to use |
| `--output-dir` | `my_results` | Directory for results |
| `--max-files` | all | Limit number of files |

#### Examples

```bash
# Audit contracts/ directory (default)
python -m app

# Audit a custom directory with 3 files
python -m app --contracts-dir my_contracts --max-files 3

# Use a different output directory
python -m app --output-dir results_v2
```

---

### 4. `generate_vul_report.py` — Standalone Report Generator

Generates MD + CSV vulnerability reports from **any** folder of `result_*.json` files.

```bash
python generate_vul_report.py <results_directory>
```

#### Available Options

| Flag | Default | Description |
|------|---------|-------------|
| `results_dir` | *(required)* | Directory containing `result_*.json` files |
| `--output` | `<results_dir>/vulnerability_report.md` | Path for Markdown report |
| `--csv` | `<results_dir>/vulnerability_report.csv` | Path for CSV report |

#### Examples

```bash
# Generate report from Zeus results
python generate_vul_report.py zeus_results

# Generate report from SmartBugs results (specific folder)
python generate_vul_report.py LOGs/my_results/access_control

# Custom output paths
python generate_vul_report.py zeus_results --output reports/vuln_report.md --csv reports/vuln_report.csv
```

---

## Configuration

### OWASP Vulnerability Categories

Located at `config/owasp_2023_categories.txt`:

| # | Category |
|---|----------|
| 1 | Reentrancy_Attacks |
| 2 | Arithmetic |
| 3 | Time_Manipulation |
| 4 | Access_Control |
| 5 | Front-running_Attacks |
| 6 | Denial_of_Service_Attacks |
| 7 | Short_Addresses |
| 8 | Insecure_Randomness |
| 9 | Unchecked_External_Calls |

### LLM Configuration

Default settings in `app/llm_client.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `temperature` | `0.0` | Near-deterministic for structured output |
| `top_p` | `0.9` | Top-p sampling |
| `num_ctx` | `24576` | Context window (24K tokens) |
| `num_predict` | `4096` | Max output tokens |
| `repeat_penalty` | `1.1` | Discourage repetitive output |
| `max_retries` | `3` | Retry on transient failures |
| `retry_delay` | `2.0s` | Base delay between retries (exponential backoff) |
| `timeout_seconds` | `300` | Per-request timeout |

---

## Output Format

### Individual Result File (`result_<name>.json`)

```json
{
  "contract_name": "simple_dao.sol",
  "contract_path": "contracts/simple_dao.sol",
  "status": "Vulnerable",
  "vulnerabilities_count": 1,
  "vulnerabilities": [
    {
      "vulnerability_type": "Reentrancy_Attacks",
      "evidence": "12-15",
      "function_name": "withdraw",
      "evidence_snippet": "msg.sender.call{value: amount}(\"\")",
      "execution": {
        "trigger": "External call before state update",
        "state_issue": "Balance not zeroed before transfer",
        "exploitable_behavior": "Attacker re-enters withdraw()"
      },
      "causality": {
        "state": "balances[msg.sender] > 0",
        "guard": "require(balances[msg.sender] >= amount)",
        "transition": "State update after external call",
        "capability": "Drain contract funds",
        "outcome": "Loss of all deposited Ether"
      }
    }
  ],
  "analysis_time_seconds": 45.32,
  "timestamp": "2026-05-10T11:30:00.000000",
  "error": null
}
```

### Status Values

| Status | Meaning |
|--------|---------|
| `Normal` | No vulnerabilities found — contract is safe |
| `Vulnerable` | One or more vulnerabilities detected |
| `Error` | Analysis failed (see `error` field) |

---

## Core Modules Reference

### `app/agent.py` — SmartContractVulnAgent

The main orchestrator that ties together prompt construction, LLM invocation, JSON extraction, and Pydantic validation.

| Method | Description |
|--------|-------------|
| `__init__(model, prompt_path, owasp_categories, host, llm_options)` | Initialize agent with model config and OWASP categories |
| `analyze(code_with_lines) → AnalysisResult` | Analyze Solidity code and return validated result (with retry) |

### `app/llm_client.py` — LLMClient

Thin wrapper around `ollama.chat` with retry logic and exponential backoff.

| Method | Description |
|--------|-------------|
| `__init__(model, host, max_retries, retry_delay, timeout_seconds, options)` | Configure the LLM client |
| `generate(system_prompt, user_prompt) → str` | Send chat request and return raw response text |

### `app/chunker.py` — Code Pre-processing

Adds line numbers and optionally chunks large contracts.

| Function | Description |
|----------|-------------|
| `chunk_whole_file(source) → CodeChunk` | Number all lines in the file, return single chunk |
| `chunk_by_lines(source, max_lines=300, overlap=20) → List[CodeChunk]` | Split large contracts into overlapping chunks |

### `app/json_extract.py` — JSON Extraction

Robust extraction from noisy LLM output (handles `<think>` tags, markdown fences, etc.).

| Function | Description |
|----------|-------------|
| `extract_json(raw) → Optional[Dict]` | Extract first valid JSON object from LLM output |

### `app/schemas.py` — Pydantic Models

| Model | Description |
|-------|-------------|
| `AnalysisResult` | Top-level output with list of vulnerabilities |
| `Vulnerability` | Single vulnerability with type, evidence, execution, causality |
| `Execution` | How the vulnerability manifests (trigger, state_issue, exploitable_behavior) |
| `Causality` | Root-cause chain (state → guard → transition → capability → outcome) |

---

## Summary of All Commands

| Command | What It Does |
|---------|-------------|
| `python run.py` | Audit all SmartBugs dataset folders + auto-generate reports |
| `python run.py --report` | Generate reports from existing SmartBugs results (no analysis) |
| `python run.py --max-files 5` | Audit max 5 contracts per folder |
| `python run.py --list-contracts` | Show the indexed SmartBugs contract list |
| `python run.py --contract-file access_control/FibonacciBalance.sol` | Audit one specific SmartBugs contract |
| `python run.py --file-range 5:10` | Audit contracts 5 through 10 from the indexed list |
| `python runzeusvul.py` | Audit Zeus contracts (with resume support) |
| `python runzeusvul.py --workers 4` | Parallel audit with 4 workers |
| `python runzeusvul.py --no-skip` | Re-analyze all Zeus contracts |
| `python runzeusvul.py --report` | Generate Zeus report only |
| `python -m app` | Audit `contracts/` directory |
| `python -m app --contracts-dir <dir>` | Audit any custom directory |
| `python generate_vul_report.py <dir>` | Generate report from any result directory |
