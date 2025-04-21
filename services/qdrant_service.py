from qdrant_client import QdrantClient
from qdrant_client.http import models
from services.ollama_service import get_embedding
from dotenv import load_dotenv

load_dotenv()


def store_in_qdrant(documents, embeddings, ids, client, collection_name = "mitre-attack"):
    """Store documents and embeddings in Qdrant"""

    # Create collection parameters
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


def query_mitre_attack(
    query: str,
    client: QdrantClient,
    collection_name: str = "mitre-attack",
    top_k: int = 3,
):
    """
    Query the Qdrant collection for similar techniques using client.search.
    """
    try:
        query_vector = get_embedding(query)
        if not isinstance(query_vector, list) or not all(
            isinstance(x, float) for x in query_vector
        ):
            print(
                f"ERROR: get_embedding did not return a valid list of floats for query: '{query}'"
            )
            return []

        search_results = client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=top_k,
            with_payload=True,
        )

        # The print statement is helpful for debugging the raw output
        print("--- Raw Search Results ---")
        print(search_results)
        print("--------------------------")

        # Format results
        formatted_results = []

        for scored_point in search_results:
            payload = scored_point.payload

            if payload is None:
                print(f"WARN: Found point with id {scored_point.id} but no payload.")
                continue

            formatted_results.append(
                {
                    "type": payload.get("type"),
                    "technique_id": payload.get("technique_id"),
                    "name": payload.get("name"),
                    "tactics": payload.get(
                        "tactics", []
                    ),  # Default to empty list if 'tactics' key is missing
                    "content": payload.get("content"),
                    "score": scored_point.score,  # Score is an attribute of ScoredPoint
                    "_id": scored_point.id,  # Optionally include the Qdrant point ID
                }
            )

        return formatted_results

    except Exception as e:
        print(f"An error occurred during the Qdrant query: {e}")
        import traceback

        traceback.print_exc()
        return []  # Return empty list on error
