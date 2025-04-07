import os
from typing import Optional
from langchain_openai import OpenAIEmbeddings
from langchain_ollama import OllamaEmbeddings


def get_embeddings(openai_api_key: Optional[str] = None, use_openai: bool = False):
    """
    Returns an appropriate embedding model based on available API keys.

    Args:
        openai_api_key: Optional OpenAI API key. If not provided, will check environment variables.

    Returns:
        An instance of OpenAIEmbeddings if an API key is available, otherwise OllamaEmbeddings.
    """
    # Check if OpenAI API key is provided or available in environment
    api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")

    if api_key and use_openai:
        return OpenAIEmbeddings(model="text-embedding-3-small")
    else:
        return OllamaEmbeddings(
            model="llama3",
            base_url="http://localhost:11434"
        )
