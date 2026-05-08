# Fixes Applied

## Problem
The script was failing with `KeyboardInterrupt` when trying to connect to Ollama. The connection was interrupted without proper error handling or diagnostics.

## Root Causes
1. No connection verification before analysis started
2. No timeout handling for Ollama requests
3. No retry logic for transient failures
4. No clear error messages about Ollama connectivity issues
5. Missing dependency: `socket` module for connection testing

## Changes Made

### 1. **app/llm_client.py** - Enhanced LLM Client
- Added `socket` import for connection verification
- Added `timeout` parameter (default 300 seconds/5 minutes)
- Added `_verify_connection()` method to check Ollama service availability
- Added retry logic with exponential backoff (1s, 2s, 4s)
- Added specific error handling for:
  - `ConnectionError` - Ollama service not running
  - `TimeoutError` - Request took too long
  - `KeyboardInterrupt` - User cancelled
  - `RuntimeError` - Other Ollama errors
- Better error messages with actionable diagnostics

### 2. **run.py** - Enhanced Error Handling
- Added pre-flight check in `run_audit()` that verifies Ollama connection before starting analysis
- Enhanced error messages to suggest solutions (e.g., "ollama serve", "ollama pull")
- Improved `analyze_contract()` error handling with specific messages for:
  - Connection errors
  - Timeout errors
  - User interruption
- Fixed typo in default output directory: `"my_result  s"` → `"my_results"`

## How to Use Now

### Before running the script:
```bash
# Terminal 1: Start Ollama service
ollama serve

# Terminal 2: Ensure model is downloaded
ollama pull deepseek-r1:7b
```

### Then run the audit:
```bash
python run.py
```

The script will now:
1. ✓ Check if Ollama is running
2. ✓ Provide helpful error messages if not
3. ✓ Retry on transient failures
4. ✓ Handle timeouts gracefully
5. ✓ Save partial results even if some contracts fail
6. ✓ Provide clear status for each contract (✓ Normal, 🚨 Vulnerable, ❌ Error)

## Configuration

To adjust timeouts (in seconds):
Edit `app/llm_client.py`:
```python
def __init__(self, model: str = "deepseek-r1:7b", timeout: int = 300):
    self.timeout = timeout  # Change this value (default 300 seconds)
```

To adjust retry attempts:
Edit the `chat()` method call in `app/agent.py` or pass `retries` parameter explicitly.
