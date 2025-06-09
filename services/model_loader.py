import os
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def load_model(use_openai=False):
    if use_openai and os.getenv("OPENAI_API_KEY"):
        model = "gpt-4o"
        logger.info(f"Using OpenAI model: {model}")
        if os.getenv("OPENAI_MODEL_NAME"):
            model = os.getenv("OPENAI_MODEL_NAME")
        return ChatOpenAI(api_key=os.getenv("OPENAI_API_KEY"), model=model)

    local_model = "qwen2.5:7b"
    logger.info(f"Using Ollama model: {local_model}")
    if os.getenv("OLLAMA_MODEL_NAME"):
        local_model = os.getenv("OLLAMA_MODEL_NAME")
    return ChatOllama(model=local_model, base_url="http://localhost:11434", temperature=0.0)
