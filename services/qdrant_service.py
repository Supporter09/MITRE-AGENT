from qdrant_client.http import models
from services.ollama_service import get_embedding
from dotenv import load_dotenv

load_dotenv()


def store_in_qdrant(documents, embeddings, ids, client):
    """Store documents and embeddings in Qdrant"""

    # Create collection parameters
    collection_name = "mitre-attack"
    dimension = len(embeddings[0])

    # Check if collection exists, if not create it
    collections = client.get_collections().collections
    collection_names = [collection.name for collection in collections]

    if collection_name not in collection_names:
        client.create_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=dimension, distance=models.Distance.COSINE
            ),
        )

    # Prepare points for upsert
    points = []
    for doc, embedding, id in zip(documents, embeddings, ids):
        points.append(
            models.PointStruct(
                id=id,  # Using the technique_id as the point ID
                vector=embedding,
                payload={
                    **doc.metadata,  # Include all metadata
                    "content": doc.page_content,  # Store the full content
                },
            )
        )

    # Upsert in batches
    batch_size = 100
    for i in range(0, len(points), batch_size):
        batch = points[i : i + batch_size]
        client.upsert(collection_name=collection_name, points=batch)

    print(f"Successfully stored {len(points)} MITRE ATT&CK techniques in Qdrant")
    return True


def query_mitre_attack(query, client, top_k=3):
    """Query the Qdrant collection for similar techniques"""

    # Search in the collection
    search_results = client.query_points(
        collection_name="mitre-attack",
        query_vector=get_embedding(query),
        limit=top_k,
    )

    print(search_results)
    # Format results
    formatted_results = []
    for result in search_results:
        technique_info = result.payload
        formatted_results.append(
            {
                "type": technique_info.get("type"),  # MITRE_ATTACK
                "technique_id": technique_info.get("technique_id"),  # e.g., T1055.011
                "name": technique_info.get("name"),
                "tactics": technique_info.get("tactics", []),
                "content": technique_info.get("content"),  # Detailed description
                "score": result.score,
            }
        )

    return formatted_results
