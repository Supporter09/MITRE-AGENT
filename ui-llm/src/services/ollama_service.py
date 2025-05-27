from langchain_ollama import OllamaEmbeddings


def generate_embeddings(documents, model = 'nomic-embed-text'):
    """Generate embeddings for documents using OpenAI API"""
    client = OllamaEmbeddings(
        model=model, base_url="http://localhost:11434"
    )

    texts = [doc.page_content for doc in documents]

    # Get embeddings for all texts in one call
    embeddings = client.embed_documents(texts)

    return embeddings


def get_embedding(text, model = 'nomic-embed-text'):
    client = OllamaEmbeddings(
        model=model, base_url="http://localhost:11434"
    )
    response = client.embed_query(text)
    return response
