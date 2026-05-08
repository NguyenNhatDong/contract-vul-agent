"""Quick smoke test for the app package."""

from app.json_extract import extract_json
from app.chunker import chunk_whole_file
from app.schemas import AnalysisResult

# 1. Test json_extract with deepseek-r1 style output
raw = (
    "<think>\nLet me analyze this contract...\n</think>\n"
    '```json\n'
    '{"vulnerabilities": [{"vulnerability_type": "Reentrancy_Attacks", '
    '"evidence": "42", "function_name": "withdraw", '
    '"evidence_snippet": "msg.sender.call{value: bal}()", '
    '"execution": {"trigger": "external call before state update", '
    '"state_issue": "balance not zeroed before call", '
    '"exploitable_behavior": "attacker re-enters withdraw"}, '
    '"causality": {"state": "balance > 0", "guard": "None", '
    '"transition": "call before balance update", '
    '"capability": "drain contract funds", '
    '"outcome": "total fund loss"}}]}\n'
    '```\n'
    'Some trailing text the model added.'
)

result = extract_json(raw)
assert result is not None, "JSON extraction failed"
assert len(result["vulnerabilities"]) == 1
print(f"[PASS] json_extract: extracted {len(result['vulnerabilities'])} vulnerability")

# 2. Test chunker
code = "pragma solidity ^0.8.0;\ncontract Test {\n  function foo() public {}\n}"
chunk = chunk_whole_file(code)
assert chunk.total_lines == 4
assert chunk.start_line == 1
assert chunk.end_line == 4
assert "1:" in chunk.code_with_lines
print(f"[PASS] chunker: {chunk.total_lines} lines numbered correctly")

# 3. Test schema validation
ar = AnalysisResult.model_validate(result)
assert len(ar.vulnerabilities) == 1
v = ar.vulnerabilities[0]
assert v.vulnerability_type == "Reentrancy_Attacks"
assert v.execution.trigger == "external call before state update"
assert v.causality.outcome == "total fund loss"
print(f"[PASS] schemas: validated vulnerability type={v.vulnerability_type}")

# 4. Test empty result
empty = extract_json('{"vulnerabilities": []}')
ar_empty = AnalysisResult.model_validate(empty)
assert len(ar_empty.vulnerabilities) == 0
print("[PASS] schemas: empty vulnerabilities list accepted")

# 5. Test json_extract repair (trailing comma)
broken = '{"vulnerabilities": [{"vulnerability_type": "Access_Control", "evidence": "10", "function_name": "setOwner", "evidence_snippet": "owner = msg.sender", "execution": {"trigger": "no auth check", "state_issue": "owner overwrite", "exploitable_behavior": "anyone calls",}, "causality": {"state": "any", "guard": "None", "transition": "missing require", "capability": "take ownership", "outcome": "full control",},},],}'
fixed = extract_json(broken)
assert fixed is not None, "JSON repair failed"
print("[PASS] json_extract: repaired trailing commas")

print("\n=== All tests passed! ===")
