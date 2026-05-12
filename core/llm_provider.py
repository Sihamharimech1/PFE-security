# core/llm_provider.py
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

class LLMProvider:
    def __init__(self, model="gpt-4o-mini", temperature=0.3):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set")

        self.model = model
        self.temperature = temperature
        self.client = OpenAI(api_key=api_key)

    def generate(self, prompt):
        last_error = None

        for _ in range(2):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are an AI agent."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature
                )
                return response.choices[0].message.content
            except Exception as exc:
                last_error = exc

        return f"LLM error: {last_error}"