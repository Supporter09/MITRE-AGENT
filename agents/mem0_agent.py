import os
import json
import requests
from typing import List, Dict, Any, Optional
import ollama
from mem0 import MemoryClient

os.environ


class MITREMemoryAgent:
    def __init__(
        self,
        ollama_model: str = "llama3",
        mem0_api_url: str = "http://localhost:8000",
        mem0_collection: str = "mitre_knowledge",
    ):
        """
        Initialize the MITRE Memory Agent with Ollama and Mem0.

        Args:
            ollama_model: The name of the Ollama model to use
            mem0_api_url: The URL for the Mem0 API
            mem0_collection: The collection name in Mem0 for MITRE data
        """
        # Initialize Ollama client
        self.model = ollama_model

        # Initialize Mem0 client
        self.mem0 = Mem0Client(api_url=mem0_api_url)
        self.collection = mem0_collection

        # Ensure the collection exists
        self._ensure_collection()

    def _ensure_collection(self):
        """Create the collection if it doesn't exist"""
        collections = self.mem0.list_collections()
        if self.collection not in collections:
            self.mem0.create_collection(self.collection)
            print(f"Created new Mem0 collection: {self.collection}")

    def load_mitre_attack_data(self, filepath: str) -> None:
        """
        Load MITRE ATT&CK data from a JSON file into Mem0.

        Args:
            filepath: Path to the MITRE ATT&CK JSON file
        """
        with open(filepath, "r") as f:
            attack_data = json.load(f)

        # Process and store techniques
        count = 0
        for technique in attack_data.get("objects", []):
            if technique.get("type") == "attack-pattern":
                technique_id = technique.get("external_references", [{}])[0].get(
                    "external_id", ""
                )
                if not technique_id.startswith("T"):
                    continue

                # Extract relevant fields
                technique_data = {
                    "id": technique_id,
                    "name": technique.get("name", ""),
                    "description": technique.get("description", ""),
                    "tactics": [
                        phase["phase_name"]
                        for phase in technique.get("kill_chain_phases", [])
                    ],
                    "platforms": technique.get("x_mitre_platforms", []),
                    "detection": technique.get("x_mitre_detection", ""),
                    "data_sources": technique.get("x_mitre_data_sources", []),
                }

                # Create the document content with detailed info
                content = f"""
                # {technique_data['id']}: {technique_data['name']}

                ## Description
                {technique_data['description']}

                ## Tactics
                {', '.join(technique_data['tactics'])}

                ## Platforms
                {', '.join(technique_data['platforms'])}

                ## Detection
                {technique_data['detection']}

                ## Data Sources
                {', '.join(technique_data['data_sources'])}
                """

                # Store in Mem0
                self.mem0.add_document(
                    collection=self.collection,
                    content=content,
                    metadata={
                        "type": "MITRE_ATTACK",
                        "technique_id": technique_data["id"],
                        "name": technique_data["name"],
                        "tactics": technique_data["tactics"],
                    },
                )
                count += 1

        print(f"Loaded {count} MITRE ATT&CK techniques into Mem0")

    def load_cwe_data(self, filepath: str) -> None:
        """
        Load CWE data from a JSON or XML file into Mem0.

        Args:
            filepath: Path to the CWE JSON or XML file
        """
        if filepath.endswith(".json"):
            with open(filepath, "r") as f:
                cwe_data = json.load(f)

            # Process based on JSON structure
            count = 0
            for weakness in cwe_data.get("weaknesses", []):
                cwe_id = weakness.get("id", "")
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"

                # Extract relevant fields
                cwe_info = {
                    "id": cwe_id,
                    "name": weakness.get("name", ""),
                    "description": weakness.get("description", ""),
                    "consequences": weakness.get("consequences", []),
                    "mitigations": weakness.get("mitigations", []),
                }

                # Create the document content
                content = f"""
                # {cwe_info['id']}: {cwe_info['name']}

                ## Description
                {cwe_info['description']}

                ## Consequences
                {self._format_list(cwe_info['consequences'])}

                ## Mitigations
                {self._format_list(cwe_info['mitigations'])}
                """

                # Store in Mem0
                self.mem0.add_document(
                    collection=self.collection,
                    content=content,
                    metadata={
                        "type": "CWE",
                        "cwe_id": cwe_info["id"],
                        "name": cwe_info["name"],
                    },
                )
                count += 1

            print(f"Loaded {count} CWE weaknesses into Mem0")
        else:
            # Handle XML format if needed
            print("XML format support not implemented. Please convert to JSON first.")

    def _format_list(self, items: List) -> str:
        """Format a list of items as a string with bullet points"""
        if not items:
            return "None specified"

        result = ""
        for item in items:
            result += f"- {item}\n"
        return result

    def search_knowledge(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Search for relevant MITRE ATT&CK techniques or CWE entries based on a query.

        Args:
            query: The search query
            limit: Maximum number of results to return

        Returns:
            List of relevant documents with their content and metadata
        """
        search_results = self.mem0.search(
            collection=self.collection, query=query, limit=limit
        )

        return search_results

    def generate_response(self, user_input: str) -> str:
        """
        Generate a response to a user query by searching Mem0 and using Ollama.

        Args:
            user_input: The user's security description or query

        Returns:
            A response from the LLM with relevant MITRE/CWE information
        """
        # Search for relevant context
        search_results = self.search_knowledge(user_input)

        # Prepare context from search results
        context = "Retrieved security knowledge:\n\n"
        for result in search_results:
            context += f"{result['content']}\n\n"

        # Build the prompt
        prompt = f"""You are a cybersecurity assistant with knowledge of MITRE ATT&CK and Common Weakness Enumeration (CWE).
Based on the user's security description, identify the most relevant MITRE techniques or CWE entries.

User Description: {user_input}

Here is relevant information from our knowledge base:
{context}

Please analyze the user description and provide:
1. Identified MITRE ATT&CK techniques or CWE weaknesses that match the description
2. Explanation of why these techniques/weaknesses are relevant
3. Recommendations for mitigation or detection methods

Your response:"""

        # Generate response using Ollama
        response = ollama.generate(
            model=self.model,
            prompt=prompt,
            system="You are a helpful cybersecurity assistant specializing in MITRE ATT&CK and CWE mapping.",
        )

        return response["response"]

    def map_security_description(self, description: str) -> Dict[str, Any]:
        """
        Maps a security description to MITRE ATT&CK techniques and CWE entries.

        Args:
            description: Security incident or vulnerability description

        Returns:
            Dictionary with mapped techniques and weaknesses
        """
        # Search for relevant ATT&CK techniques
        attack_query = f"MITRE ATT&CK technique for: {description}"
        attack_results = self.mem0.search(
            collection=self.collection,
            query=attack_query,
            filter={"type": "MITRE_ATTACK"},
            limit=3,
        )

        # Search for relevant CWE entries
        cwe_query = f"Common Weakness Enumeration for: {description}"
        cwe_results = self.mem0.search(
            collection=self.collection, query=cwe_query, filter={"type": "CWE"}, limit=3
        )

        # Generate comprehensive analysis using the LLM
        context = ""
        for result in attack_results:
            context += f"ATT&CK: {result['content']}\n\n"

        for result in cwe_results:
            context += f"CWE: {result['content']}\n\n"

        prompt = f"""Given this security description:
"{description}"

And these potential matches from MITRE ATT&CK and CWE:
{context}

Provide a comprehensive analysis including:
1. Most relevant ATT&CK techniques and why they match
2. Most relevant CWE weaknesses and why they match
3. Potential relationships between the identified techniques and weaknesses
4. Recommended detection and mitigation strategies

Format your response as a detailed security analysis report."""

        # Generate the analysis using Ollama
        analysis = ollama.generate(
            model=self.model,
            prompt=prompt,
            system="You are a cybersecurity expert specializing in mapping security incidents to MITRE ATT&CK and CWE frameworks.",
        )

        # Return structured results
        return {
            "description": description,
            "attack_techniques": [r["metadata"] for r in attack_results],
            "cwe_entries": [r["metadata"] for r in cwe_results],
            "analysis": analysis["response"],
        }


# Example usage
if __name__ == "__main__":
    # Initialize the agent
    agent = MITREMemoryAgent(
        ollama_model="llama3",
        mem0_api_url="http://localhost:8000",
        mem0_collection="mitre_security_knowledge",
    )

    # Load data from files
    agent.load_mitre_attack_data("enterprise-attack.json")
    agent.load_cwe_data("cwe_database.json")

    # Example query
    user_description = "Our logs show attackers exploited a SQL injection vulnerability to access our customer database and exfiltrated data through encrypted channels."

    # Get mapping and analysis
    results = agent.map_security_description(user_description)

    # Print results
    print(json.dumps(results, indent=2))
