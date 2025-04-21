from langchain_ollama import OllamaEmbeddings


def generate_embeddings(documents):
    """Generate embeddings for documents using OpenAI API"""
    client = OllamaEmbeddings(
        model="llama3", base_url="http://localhost:11434"
    )

    texts = [doc.page_content for doc in documents]

    # Get embeddings for all texts in one call
    embeddings = client.embed_documents(texts)

    return embeddings


def get_embedding(text):
    client = OllamaEmbeddings(
        model="llama3", base_url="http://localhost:11434"
    )
    response = client.embed_query(text)
    return response
