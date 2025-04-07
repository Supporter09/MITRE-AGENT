import os
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama

def load_model(use_openai=False):
    if use_openai and os.getenv("OPENAI_API_KEY"):
        return ChatOpenAI(api_key=os.getenv("OPENAI_API_KEY"), model="gpt-4")
    return ChatOllama(model="qwen2.5:7b", base_url="http://localhost:11434", temperature=0.0)
