from dataclasses import dataclass

@dataclass
class Chunk:
    code_with_lines: str

def chunk_whole_file(sol_text: str) -> Chunk:
    lines = sol_text.splitlines()
    code_with_lines = "\n".join([f"{i+1}| {line}" for i, line in enumerate(lines)])
    return Chunk(code_with_lines=code_with_lines)