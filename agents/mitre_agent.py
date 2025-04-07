from resources.resources import *
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langchain.tools import Tool
from langgraph.prebuilt import create_react_agent
import os
from mem0 import MemoryClient
from qdrant_client import QdrantClient
from qdrant_client.http import models
from langgraph.store.memory import InMemoryStore
from langmem import create_manage_memory_tool, create_search_memory_tool
from services.embed_loader import get_embeddings
from services.qdrant_service import query_mitre_attack
from utils.utils import *


class MitreAttackAgent:
    def __init__(self, use_openai=False):
        # Initialize environment variables and clients
        self.setup_environment()

        # Initialize AI model
        self.model = self.setup_model(use_openai)

        # Initialize memory store
        self.store = InMemoryStore(
            index={
                "dims": 1536,
                "embed": get_embeddings(),
            }
        )

        # Initialize agent
        self.agent = self.create_agent()

    def setup_environment(self):
        """Set up environment variables and initialize clients"""
        # Environment variables
        os.environ["MEM0_API_KEY"] = os.environ.get("MEM0_API_KEY")
        os.environ["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")

        # Clients
        self.mem0_client = MemoryClient()
        self.mem0_collection = "mitre_attack"

        self.qdrant_url = os.environ.get("QDRANT_URL")
        self.qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        self.qdrant_client = QdrantClient(
            url=self.qdrant_url,
            api_key=self.qdrant_api_key,
        )

    def setup_model(self, use_openai):
        """Set up the LLM based on configuration"""
        if use_openai and os.environ.get("OPENAI_API_KEY"):
            return ChatOpenAI(api_key=os.environ.get("OPENAI_API_KEY"), model="gpt-4")
        else:
            return ChatOllama(
                model="qwen2.5:7b", temperature=0.0, base_url="http://localhost:11434"
            )

    def retrieve_attack_techniques(self, query):
        """Tool to retrieve relevant MITRE ATT&CK techniques from Qdrant."""
        techniques = query_mitre_attack(query, client=self.qdrant_client)

        if not techniques:
            return "No relevant techniques found."

        print(techniques)
        result = "Retrieved relevant MITRE ATT&CK techniques:\n\n"
        for i, tech in enumerate(techniques, 1):
            result += f"{i}. {tech['name']} ({tech['technique_id']})\n"
            result += f"   Tactics: {', '.join(tech['tactics'])}\n"
            result += f"   Description: {tech['content'][:200]}...\n\n"

        return result

    def get_technique_details(self, technique_id):
        """Tool to get detailed information about a specific technique by ID."""
        search_results = self.qdrant_client.scroll(
            collection_name="mitre-attack",
            scroll_filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="technique_id", match=models.MatchValue(value=technique_id)
                    )
                ]
            ),
            limit=1,
        )[0]

        if not search_results:
            return f"No technique found with ID: {technique_id}"

        technique = search_results[0].payload
        result = f"# {technique['name']} ({technique['technique_id']})\n\n"
        result += f"**Tactics**: {', '.join(technique['tactics'])}\n\n"
        result += f"**Description**:\n{technique['content']}\n"

        return result

    def mitre_attack_tool(self, query):
        """Process attack scenario description and map to MITRE ATT&CK."""
        prompt = gSce2MitrePrompt + f"\nScenario:\n{query}"
        response = self.model.invoke(prompt)
        return response if response else "No relevant MITRE ATT&CK data found."

    def verify_attack_technique(self, technique_id, scenario):
        """Verify whether the technique is correctly mapped to the attack scenario."""
        technique_details = self.get_technique_details(technique_id)

        verification_prompt = f"""
        Verify whether the following MITRE ATT&CK technique applies to the attack scenario:

        Scenario:
        {scenario}

        Technique information:
        {technique_details}

        Analyze whether this technique matches the scenario and explain why. Use the following format:

        match: Yes/No
        explanation: <Brief summary of how the technique matches or doesn't match the scenario>
        """

        response = self.model.invoke(verification_prompt)
        return response

    def create_agent(self):
        """Create the MITRE agent with the defined tools"""
        return create_react_agent(
            model=self.model,
            tools=[
                self.mitre_attack_tool,
                self.verify_attack_technique,
                self.retrieve_attack_techniques,
                self.get_technique_details,
                create_manage_memory_tool(namespace=("mitre_memories", "{user_id}")),
                create_search_memory_tool(namespace=("mitre_memories", "{user_id}")),
            ],
            name="mitre_expert",
            prompt=gAgentPrompt,
        )

    def invoke(self, query, thread_id, user_id):
        """Public method to invoke the agent with a query"""
        messages = [{"role": "user", "content": query}]
        return self.agent.invoke(
            {"messages": messages},
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "user_id": user_id,
                }
            },
        )
