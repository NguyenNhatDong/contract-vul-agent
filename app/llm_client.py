import ollama

class LLMClient:
    def __init__(self, model: str = "deepseek-r1:7b"):
        self.model = model

    def chat(self, prompt: str, temperature: float = 0.2) -> str:
        resp = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": temperature}
        )
        return resp["message"]["content"]