import json
import uuid
import os
from dotenv import load_dotenv
from qdrant_client.http import models
from services.ollama_service import get_embedding
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

load_dotenv()

def load_semgrep_rules(file_path: str) -> List[Dict[str, Any]]:
    """
    Load Semgrep rules from a JSON file.

    Args:
        file_path: Path to the JSON file containing Semgrep rules

    Returns:
        List of rule dictionaries
    """
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Handle different possible formats for Semgrep rules
    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict) and 'rules' in data:
        rules = data['rules']
    else:
        raise ValueError("Unexpected Semgrep rules format")
    
    return rules

def process_semgrep_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Process Semgrep rules to extract only the needed fields.

    Args:
        rules: List of raw rule dictionaries

    Returns:
        List of processed rule dictionaries
    """
    processed_rules = []
    for rule in rules:
        # Only extract id, message, and fix-suggestion
        processed_rule = {
            "rule_id": rule.get("id", ""),
            "message": rule.get("message", ""),
            "fix_suggestion": rule.get("metadata", {}).get("fix-suggestion", ""),
            # Create a UUID for Qdrant
            "uuid": str(uuid.uuid4())
        }
        
        # Create a content field for embedding generation
        processed_rule["content"] = f"""
        Rule ID: {processed_rule['rule_id']}
        
        Message: {processed_rule['message']}
        
        Fix Suggestion: {processed_rule['fix_suggestion']}
        """
        
        processed_rules.append(processed_rule)
    
    return processed_rules

def attach_embedding(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Helper function to compute and attach the embedding to a rule dictionary.
    
    Args:
        rule: Processed rule dictionary with a 'content' key
    
    Returns:
        The same rule dictionary with an 'embedding' key added.
    """
    rule['embedding'] = get_embedding(rule["content"])
    return rule

def store_semgrep_rules_in_qdrant(rules: List[Dict[str, Any]], client) -> bool:
    """
    Store processed Semgrep rules in Qdrant with concurrent embedding generation and progress display.

    Args:
        rules: List of processed rule dictionaries
        client: Qdrant client instance

    Returns:
        True if successful
    """
    collection_name = "semgrep-rules"

    # Concurrently compute embeddings for each rule using ThreadPoolExecutor.
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(attach_embedding, rule) for rule in rules]
        # Display progress using tqdm while waiting for embeddings
        for future in tqdm(as_completed(futures), total=len(futures), desc="Generating Embeddings"):
            # Propagate any exceptions
            future.result()
    
    # After embeddings are attached, determine the dimension from a sample.
    sample_embedding = rules[0]["embedding"]
    dimension = len(sample_embedding)
    
    # Check if collection exists, if not create it.
    collections = client.get_collections().collections
    collection_names = [collection.name for collection in collections]
    
    if collection_name not in collection_names:
        client.create_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=dimension, distance=models.Distance.COSINE
            ),
        )
    
    # Prepare points for upsert using the pre-computed embeddings.
    points = []
    for rule in rules:
        points.append(
            models.PointStruct(
                id=rule["uuid"],  # Using UUID as Qdrant ID
                vector=rule["embedding"],
                payload={
                    "rule_id": rule["rule_id"],
                    "message": rule["message"],
                    "fix_suggestion": rule["fix_suggestion"],
                    "content": rule["content"]
                },
            )
        )
    
    # Upsert in batches with a progress bar
    batch_size = 10
    for i in tqdm(range(0, len(points), batch_size), desc="Uploading to Qdrant"):
        batch = points[i : i + batch_size]
        client.upsert(collection_name=collection_name, points=batch)
    
    print(f"Successfully stored {len(points)} Semgrep rules in Qdrant")
    return True

def query_semgrep_rules(code: str, client, top_k=3):
    """
    Query the Qdrant collection for Semgrep rules that match the provided code.

    Args:
        code: Vulnerable code to check
        client: Qdrant client instance
        top_k: Number of results to return

    Returns:
        List of matching rules
    """
    # Generate embedding for the code.
    code_embedding = get_embedding(code)
    
    # Search in the collection.
    search_results = client.search(
        collection_name="semgrep-rules",
        query_vector=code_embedding,
        limit=top_k,
    )
    
    # Format results.
    formatted_results = []
    for result in search_results:
        rule_info = result.payload
        formatted_results.append({
            "rule_id": rule_info.get("rule_id"),
            "message": rule_info.get("message"),
            "fix_suggestion": rule_info.get("fix_suggestion"),
            "score": result.score,
        })
    
    return formatted_results
