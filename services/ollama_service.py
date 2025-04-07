from langchain_ollama import OllamaEmbeddings

def generate_embeddings(documents):
    """Generate embeddings for documents using OpenAI API"""
    client = OllamaEmbeddings(model="llama3", base_url="http://localhost:11434")

    embeddings = []
    for doc in documents:
        # Get embedding directly using the client object
        embedding = client.embed_query(doc.page_content)
        embeddings.append(embedding)

    return embeddings

def get_embedding(text):
    client = OllamaEmbeddings(model="llama3", base_url="http://localhost:11434")
    response = client.embed_query(text)
    return response
