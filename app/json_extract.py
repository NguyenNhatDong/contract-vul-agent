import re

def extract_json_object(text: str) -> str:
    """Extract JSON object from LLM output, handling markdown and text noise."""
    
    # Remove markdown code fences if present
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text)
    
    # Find first { and last }
    start = text.find("{")
    end = text.rfind("}")
    
    if start == -1 or end == -1 or end <= start:
        # Show first 1000 chars to help debug
        preview = text[:1000] if len(text) > 1000 else text
        raise ValueError(
            f"No JSON object found in model output.\n"
            f"Output preview (first 1000 chars):\n{preview}"
        )
    
    return text[start:end+1]