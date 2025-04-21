#!/usr/bin/env python3

import os
import sys
import argparse
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from services.semgrep_service import load_semgrep_rules, process_semgrep_rules, store_semgrep_rules_in_qdrant

# Add the parent directory to sys.path to import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    """Main function to import Semgrep rules into Qdrant."""
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Import Semgrep rules into Qdrant")
    parser.add_argument("--file", "-f", required=True, help="Path to Semgrep rules JSON file")
    args = parser.parse_args()
    
    # Check if the file exists
    if not os.path.exists(args.file):
        print(f"Error: File {args.file} does not exist")
        sys.exit(1)
    
    # Initialize Qdrant client
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_api_key = os.environ.get("QDRANT_API_KEY")
    
    if not qdrant_url:
        print("Error: QDRANT_URL environment variable not set")
        sys.exit(1)
    
    qdrant_client = QdrantClient(
        url=qdrant_url,
        api_key=qdrant_api_key,
    )
    
    try:
        # Load Semgrep rules
        print(f"Loading Semgrep rules from {args.file}...")
        rules = load_semgrep_rules(args.file)
        print(f"Loaded {len(rules)} rules")
        
        # Process Semgrep rules
        print("Processing rules...")
        processed_rules = process_semgrep_rules(rules)
        
        # Store in Qdrant
        print("Storing rules in Qdrant...")
        store_semgrep_rules_in_qdrant(processed_rules, qdrant_client)
        
        print("Import completed successfully!")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()