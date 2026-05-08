# Smart Contract Auditing Script Summary

## Overview
The `run.py` script automates the vulnerability auditing process for Solidity smart contracts using the `SmartContractVulnAgent` powered by Ollama models.

## Key Features Implemented

### 1. **Initialization**
- Loads OWASP 2023 Smart Contract vulnerability categories from `config/owasp_2023_categories.txt`
- Initializes `SmartContractVulnAgent` with:
  - Model name: `deepseek-r1:7b` (default, configurable)
  - System prompt path: `prompts/detect_vuln_prompt.txt`
  - List of vulnerability categories

### 2. **File Processing**
- Iterates through all `.sol` files in the `contracts/` directory (recursive)
- Supports limiting analysis to a maximum number of files via `--max-files`
- Provides progress tracking with indexed output (e.g., `[1/100]`)

### 3. **Code Formatting**
- Uses the `chunker.chunk_whole_file()` function to format code with line numbers
- Format: `{line_number}| {code_line}`
- Required to fill the `<CODE_WITH_LINES>` placeholder in the prompt

### 4. **Analysis**
- Calls `agent.analyze(code_with_lines)` for each contract
- Identifies vulnerabilities from the provided OWASP set
- Handles analysis errors gracefully with retry mechanism for JSON parsing
- Measures analysis time for each contract

### 5. **Output Structure**
The script handles structured JSON output with the following fields:

**Per-Vulnerability Information:**
- `vulnerability_type`: Type of vulnerability detected
- `evidence`: Code evidence from the contract
- `execution`: Contains:
  - `trigger`: How the vulnerability is triggered
  - `state_issue`: State-related issues
  - `exploitable_behavior`: Exploitation details
- `causality`: Root cause analysis:
  - `state`: State conditions
  - `guard`: Guard conditions
  - `transition`: State transitions
  - `capability`: Required capabilities
  - `outcome`: Attack outcome

**Per-Contract Status:**
- `status`: "Normal" (safe), "Vulnerable", or "Error"

### 6. **Results Export**
- Aggregates all analysis results into a single JSON file: `outputs/audit_results.json`
- Includes:
  - `audit_metadata`: Timestamp, model, categories count, total time
  - `summary`: Statistics including:
    - Total contracts analyzed
    - Count of vulnerable vs safe contracts
    - Total vulnerabilities found
    - Distribution by vulnerability type
  - `audit_results`: Detailed results for each contract

## Usage

### Basic Usage
```bash
python run.py
```

### With Custom Parameters
```bash
# Analyze only 10 contracts
python run.py --max-files 10

# Use different output directory
python run.py --output-dir my_results

# Use different model
python run.py --model llama2

# Custom configuration paths
python run.py --config custom_config.txt --prompt custom_prompt.txt
```

### Command-Line Arguments
- `--contracts-dir`: Directory containing .sol files (default: `contracts`)
- `--config`: Path to OWASP categories config (default: `config/owasp_2023_categories.txt`)
- `--prompt`: Path to system prompt template (default: `prompts/detect_vuln_prompt.txt`)
- `--model`: Ollama model to use (default: `deepseek-r1:7b`)
- `--output-dir`: Directory to save results (default: `outputs`)
- `--max-files`: Limit number of files to analyze (default: all)

### Help
```bash
python run.py --help
```

## Output Example

### Console Output
```
🔐 Smart Contract Vulnerability Audit
==================================================
Model: deepseek-r1:7b
Categories: 10
Total contracts: 25
Output directory: outputs
==================================================

🔍 Starting analysis...

[1/25] Analyzing contract1.sol... ✓ Normal (2.45s, 0 vulns)
[2/25] Analyzing contract2.sol... 🚨 Vulnerable (3.12s, 2 vulns)
...
[25/25] Analyzing contract25.sol... ✓ Normal (1.89s, 0 vulns)

==================================================
✅ Audit Complete!
==================================================
Total contracts analyzed: 25
Vulnerable contracts: 3
Safe contracts: 22
Failed analyses: 0
Total vulnerabilities: 5
Total time: 75.23s

Vulnerability Types Found:
  - Reentrancy Attacks: 2
  - Integer Overflow: 2
  - Access Control Vulnerabilities: 1

📁 Results saved to: outputs/audit_results.json
```

### JSON Output (`audit_results.json`)
```json
{
  "audit_metadata": {
    "timestamp": "2024-04-20T15:30:45.123456",
    "model": "deepseek-r1:7b",
    "owasp_categories": 10,
    "total_time_seconds": 75.23
  },
  "summary": {
    "total_contracts": 25,
    "successful_analyses": 25,
    "failed_analyses": 0,
    "vulnerable_contracts": 3,
    "safe_contracts": 22,
    "total_vulnerabilities_found": 5,
    "average_analysis_time_seconds": 3.01,
    "vulnerability_types_distribution": {
      "Reentrancy Attacks": 2,
      "Integer Overflow": 2,
      "Access Control Vulnerabilities": 1
    }
  },
  "audit_results": [
    {
      "contract_name": "contract1.sol",
      "contract_path": "contracts/contract1.sol",
      "status": "Normal",
      "vulnerabilities_count": 0,
      "vulnerabilities": [],
      "analysis_time_seconds": 2.45,
      "error": null
    },
    {
      "contract_name": "contract2.sol",
      "contract_path": "contracts/contract2.sol",
      "status": "Vulnerable",
      "vulnerabilities_count": 2,
      "vulnerabilities": [
        {
          "vulnerability_type": "Reentrancy Attacks",
          "evidence": "45| msg.sender.call.value(amount)()",
          "execution": {
            "trigger": "External call to attacker contract",
            "state_issue": "Balance updated after external call",
            "exploitable_behavior": "Attacker can re-enter to drain contract"
          },
          "causality": {
            "state": "Account balance state",
            "guard": "No guard against reentrancy",
            "transition": "Balance decremented after call",
            "capability": "Attacker needs malicious fallback function",
            "outcome": "Drain contract balance"
          }
        }
      ],
      "analysis_time_seconds": 3.12,
      "error": null
    }
  ]
}
```

## Error Handling
- **Missing .sol files**: Script reports and exits gracefully
- **Analysis failures**: Individual contract failures are logged without stopping the audit
- **JSON parsing errors**: Automatic retry with strict JSON enforcement
- **Interrupted by user**: Graceful handling of keyboard interrupt

## Performance Considerations
- Processes contracts sequentially
- Supports limiting analysis with `--max-files` for testing
- Average analysis time depends on:
  - Model used
  - Contract size
  - System resources
  - Ollama service availability

## Dependencies
The script requires:
- Python 3.8+
- `ollama` Python package
- Local Ollama service running on port 11434 (default)
- The specified model pulled in Ollama

## Integration with Existing Components
- **`SmartContractVulnAgent`**: Handles vulnerability detection
- **`chunker.chunk_whole_file()`**: Formats code with line numbers
- **`LLMClient`**: Manages communication with Ollama
- **`DetectionOutput` schema**: Validates and structures results
