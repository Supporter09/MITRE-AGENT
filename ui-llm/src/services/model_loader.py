import os
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama

def load_model(use_openai=False):
    if use_openai and os.getenv("OPENAI_API_KEY"):
        model = "gpt-4o"
        if os.getenv("OPENAI_MODEL_NAME"):
            model = os.getenv("OPENAI_MODEL_NAME")
        return ChatOpenAI(api_key=os.getenv("OPENAI_API_KEY"), model=model)
    
    local_model = "qwen2.5:7b"
    if os.getenv("OLLAMA_MODEL_NAME"):
        local_model = os.getenv("OLLAMA_MODEL_NAME")
    return ChatOllama(model=local_model, base_url="http://localhost:11434", temperature=0.0)
