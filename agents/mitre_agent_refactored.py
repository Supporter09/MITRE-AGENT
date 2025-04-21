# --- START OF FILE mitre_agent_refactored.py ---

import os
import json
from typing import Literal, TypedDict, Annotated, List, Dict, Optional
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    ToolMessage,
    SystemMessage,
)
from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from mem0 import MemoryClient
from qdrant_client import QdrantClient
from qdrant_client.http import models
from services.embed_loader import get_embeddings
from services.qdrant_service import query_mitre_attack
from utils.utils import *


# --- Agent State Definition ---
class MitreAgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    user_query: str
    memory_context: Optional[str]
    intent: Optional[
        Literal["mitre_mapping", "general_qa"]
    ]  # **** NEW: Stores classified intent ****
    retrieved_techniques: List[Dict]
    processed_techniques: List[Dict]
    final_report: Optional[str]  # Can be MITRE report or Q&A answer
    user_id: str
    thread_id: str


class MitreAttackAgent:
    def __init__(self, use_openai=False):
        self.setup_environment()
        self.model = self.setup_model(use_openai)
        self._setup_tools()
        self.graph = self._build_graph()
        self.agent = self.graph.compile()
        print(
            f"MitreAttackAgent initialized. Using model: {'OpenAI' if use_openai else 'Ollama'}. Mem0 Collection: {self.mem0_collection}"
        )

    def setup_environment(self):
        """Set up environment variables and initialize clients"""
        os.environ["MEM0_API_KEY"] = os.environ.get("MEM0_API_KEY")
        os.environ["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")

        # Check for Mem0 API Key
        if not os.environ.get("MEM0_API_KEY"):
            print("Warning: MEM0_API_KEY not found. Memory functions will likely fail.")

        self.mem0_client = MemoryClient()
        self.mem0_collection = "mitre_memories"

        self.qdrant_url = os.environ.get("QDRANT_URL")
        self.qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        self.qdrant_client = QdrantClient(
            url=self.qdrant_url,
            api_key=self.qdrant_api_key,
        )
        self.mitre_collection_name = "mitre-attack"

    def setup_model(self, use_openai):
        """Set up the LLM based on configuration"""
        if use_openai and os.environ.get("OPENAI_API_KEY"):
            print("Using OpenAI GPT-4 model.")
            return ChatOpenAI(
                api_key=os.environ.get("OPENAI_API_KEY"), model="gpt-4", temperature=0.0
            )
        else:
            print("Using Ollama qwen2.5:7b model.")
            # Ensure Ollama server is running at the base_url
            return ChatOllama(
                model="qwen2.5:7b", temperature=0.0, base_url="http://localhost:11434"
            )

    def _setup_tools(self):
        """Define helper methods that will be used by graph nodes."""
        # These are not wrapped in @tool unless meant to be called reactively by an LLM node (less likely in this structured graph)
        pass  # Methods below act as the tools

    # --- Tool-like Methods (called by graph nodes) ---

    def _retrieve_attack_techniques(self, query: str) -> List[Dict]:
        """Retrieves relevant MITRE ATT&CK techniques from Qdrant."""
        print(f"Retrieving techniques for query: {query}")
        techniques = query_mitre_attack(
            query, client=self.qdrant_client, collection_name=self.mitre_collection_name
        )  # Ensure collection_name is passed if needed
        if not techniques:
            print("No relevant techniques found in Qdrant.")
            return []
        print(f"Found {len(techniques)} potential techniques.")

        return techniques

    def _get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Gets detailed information about a specific technique by ID."""
        print(f"Getting details for technique: {technique_id}")
        try:
            search_results = self.qdrant_client.scroll(
                collection_name=self.mitre_collection_name,
                scroll_filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="technique_id",
                            match=models.MatchValue(value=technique_id),
                        )
                    ]
                ),
                limit=1,
                with_payload=True,  # Ensure payload is returned
            )[
                0
            ]  # scroll returns tuple (records, next_page_offset)

            if not search_results:
                print(f"No technique found with ID: {technique_id}")
                return None

            # Access payload correctly - scroll returns PointStruct objects
            technique = search_results[0].payload
            print(f"Details found for {technique_id}: {technique.get('name', 'N/A')}")
            return technique  # Return the full payload dict
        except Exception as e:
            print(f"Error getting details for technique {technique_id}: {e}")
            return None

    def _verify_attack_technique(self, technique_details: Dict, scenario: str) -> Dict:
        """Verifies whether the technique is correctly mapped to the attack scenario using the LLM."""
        technique_id = technique_details.get("technique_id", "N/A")
        technique_name = technique_details.get("name", "N/A")
        print(
            f"Verifying technique {technique_id} ({technique_name}) against scenario."
        )

        technique_info_str = f"# {technique_name} ({technique_id})\n\n"
        technique_info_str += (
            f"**Tactics**: {', '.join(technique_details.get('tactics', []))}\n\n"
        )
        technique_info_str += f"**Description**:\n{technique_details.get('content', 'No description available.')}\n"  # Adjust keys based on your payload

        verification_prompt = f"""
        You are a cybersecurity analyst. Verify if the following MITRE ATT&CK technique accurately applies to the given attack scenario.

        **Attack Scenario:**
        {scenario}

        **MITRE ATT&CK Technique Information:**
        {technique_info_str}

        **Analysis Task:**
        1. Carefully compare the scenario's actions, goals, or observed artifacts with the technique's description and typical usage.
        2. Determine if the technique is a plausible match for the scenario.
        3. Provide a concise explanation for your conclusion.

        **Output Format (JSON):**
        Output ONLY a valid JSON object with the following keys:
        - "match": boolean (true if it matches, false otherwise)
        - "explanation": string (A brief summary of how the technique matches or doesn't match the scenario. Be specific.)

        Example JSON Output:
        {{
          "match": true,
          "explanation": "The scenario describes lateral movement using stolen credentials, which aligns directly with this technique's description of using valid accounts."
        }}
        """

        try:
            response = self.model.invoke(verification_prompt)
            # Attempt to parse the JSON response, handling potential errors
            content = (
                response.content if hasattr(response, "content") else str(response)
            )
            # Clean potential markdown fences ```json ... ```
            if content.strip().startswith("```json"):
                content = content.strip()[7:-3].strip()
            elif content.strip().startswith("```"):
                content = content.strip()[3:-3].strip()

            verification_result = json.loads(content)
            if (
                isinstance(verification_result, dict)
                and "match" in verification_result
                and "explanation" in verification_result
            ):
                print(f"Verification result for {technique_id}: {verification_result}")
                return {
                    "technique_id": technique_id,
                    "name": technique_name,
                    "match": verification_result.get("match", False),
                    "explanation": verification_result.get("explanation", "N/A"),
                }
            else:
                print(
                    f"Warning: Verification response for {technique_id} was not in the expected JSON format. Response: {content}"
                )
                # Fallback: Treat as non-matching if format is wrong
                return {
                    "technique_id": technique_id,
                    "name": technique_name,
                    "match": False,
                    "explanation": "LLM response format error.",
                }

        except json.JSONDecodeError as e:
            print(
                f"Error decoding verification JSON for {technique_id}: {e}. Response: {content}"
            )
            return {
                "technique_id": technique_id,
                "name": technique_name,
                "match": False,
                "explanation": "LLM response JSON decode error.",
            }
        except Exception as e:
            print(f"Error during LLM verification call for {technique_id}: {e}")
            return {
                "technique_id": technique_id,
                "name": technique_name,
                "match": False,
                "explanation": f"LLM invocation error: {e}",
            }

    def _generate_final_report_mitre(
        self,
        scenario: str,
        processed_techniques: List[Dict],
        memory_context: Optional[str],
    ) -> str:
        """Generates the final report, incorporating memory context."""
        print("Generating final report...")
        if not processed_techniques:
            return "No relevant MITRE ATT&CK techniques were identified or verified for the given scenario."

        # matched_techniques = [t for t in processed_techniques if t.get('match')]
        # considered_techniques = processed_techniques # Or only non-matches

        context_section = ""
        if memory_context:
            context_section = f"""
        **Relevant Previous Context:**
        {memory_context}
        ---
        """

        report_prompt = f"""
        You are a cybersecurity analyst summarizing MITRE ATT&CK mapping findings.

        {context_section}
        **Current Attack Scenario:**
        {scenario}

        **Analysis Results for Current Scenario:**
        Techniques analyzed:
        {json.dumps(processed_techniques, indent=2, default=str)}

        **Task:**
        Generate a concise report for the user that:
        1. Briefly restates the user's scenario (1 sentence).
        2. Lists the MITRE ATT&CK techniques identified as **matching** the scenario, including their ID, name, and the explanation for the match.
        3. Optionally, briefly mention techniques that were considered but deemed not to match, if appropriate (keep this very short or omit if many).
        4. Conclude with a summary statement.

        **Format:**
        Use clear headings and bullet points for readability. Focus on the *matched* techniques primarily.

        Example Structure:
        ## MITRE ATT&CK Mapping Report

        **Scenario:** A brief summary of the user's input.

        **Matching Techniques:**
        *   **Txxxx (Technique Name):** Explanation why it matches...
        *   **Tyyyy (Technique Name):** Explanation why it matches...

        **(Optional) Considered Techniques (Not Matched):**
        *   Tzzzz (Technique Name): Reason for not matching...

        **Conclusion:** A brief summary of the findings.
        """

        try:
            response = self.model.invoke(report_prompt)
            report = response.content if hasattr(response, "content") else str(response)
            print("Final report generated.")
            return report
        except Exception as e:
            print(f"Error generating final report: {e}")
            return f"Error generating report: {e}"

    # --- Mem0 Memory Tools ---
    def _add_memory(self, user_id: str, session_id: str, messages: List[BaseMessage]):
        """Adds interaction messages to Mem0 using contextual v2 format."""
        if not self.mem0_client or not os.getenv("MEM0_API_KEY"):
            print("Skipping add memory: Mem0 client not available or API key missing.")
            return "Memory not saved (client/key unavailable)."

        print(
            f"Adding conversation memory for user {user_id}, session {session_id} (v2)"
        )
        try:
            # Convert BaseMessages to Mem0's expected format if needed, or pass directly if compatible
            # Mem0 expects [{"role": "user/assistant/system", "content": "text"}]
            mem0_formatted_messages = []
            for msg in messages:
                role = (
                    "assistant"
                    if isinstance(msg, AIMessage)
                    else "system" if isinstance(msg, SystemMessage) else "user"
                )  # Default to user for HumanMessage or others
                if hasattr(msg, "content"):
                    mem0_formatted_messages.append(
                        {"role": role, "content": msg.content}
                    )

            if not mem0_formatted_messages:
                print("No messages to add to memory.")
                return "No messages to save."

            # Get metadata from instance if available (set in process/qa nodes)
            metadata = getattr(self, "current_memory_metadata", {})

            response = self.mem0_client.add(
                mem0_formatted_messages,
                user_id=user_id,
                session_id=session_id,  # Use thread_id as session_id
                collection=self.mem0_collection,
                version="v2",
                metadata=metadata,
            )
            print(f"Memory added successfully via v2 format. Response: {response}")
            return "Memory saved (v2)."
        except Exception as e:
            print(
                f"Error adding memory (v2) for user {user_id}, session {session_id}: {e}"
            )
            return f"Error saving memory (v2): {e}"

    def _search_memory(
        self, query: str, user_id: str, session_id: str
    ) -> Optional[str]:
        """Searches Mem0 for relevant past context."""
        if not self.mem0_client or not os.getenv("MEM0_API_KEY"):
            print(
                "Skipping search memory: Mem0 client not available or API key missing."
            )
            return None

        print(
            f"Searching memory for user {user_id}, session {session_id} with query: {query}"
        )
        try:
            # Search within the specific session first, potentially broaden later if needed
            relevant_memories = self.mem0_client.search(
                query=query,
                user_id=user_id,
                session_id=session_id,
                collection=self.mem0_collection,
                limit=3,  # Get top 3 relevant memories
            )
            print(f"Memory search raw results: {relevant_memories}")
            if relevant_memories:
                # Format results into a string context
                context_str = "Found relevant context from past interactions:\n"

                context = "\n".join([m["memory"] for m in relevant_memories])

                context_str += f"---\n{context}"

                return context_str.strip()
            else:
                print("No relevant memories found.")
                return None
        except Exception as e:
            print(
                f"Error searching memory for user {user_id}, session {session_id}: {e}"
            )
            return f"Error searching memory: {e}"  # Return error message as context? Or None? Let's return None.

    # --- Graph Definition ---

    def _build_graph(self):
        """Builds the LangGraph StateGraph with intent classification and routing."""
        workflow = StateGraph(MitreAgentState)

        # Define Nodes
        workflow.add_node("search_memory", self.execute_search_memory)
        workflow.add_node("classify_intent", self.execute_classify_intent)
        workflow.add_node("retrieve_techniques", self.execute_retrieve)
        workflow.add_node("process_techniques", self.execute_process_techniques)
        workflow.add_node("generate_report_mitre", self.execute_generate_report_mitre)
        workflow.add_node("generate_qa_response", self.execute_generate_qa_response)
        workflow.add_node("save_memory", self.execute_save_memory)

        # Define Edges
        workflow.set_entry_point("search_memory")
        workflow.add_edge(
            "search_memory", "classify_intent"
        )  # Search first, then classify

        workflow.add_conditional_edges(
            "classify_intent",  # Source node
            self.route_based_on_intent,  # Function to decide the next node
            {  # Mapping: output of function -> destination node
                "mitre_mapping": "retrieve_techniques",
                "general_qa": "generate_qa_response",
                "fallback": END,  # Optional: End if classification fails badly
            },
        )

        # MITRE Path
        workflow.add_edge("retrieve_techniques", "process_techniques")
        workflow.add_edge("process_techniques", "generate_report_mitre")
        workflow.add_edge("generate_report_mitre", "save_memory")  # Merge to save

        # Q&A Path
        workflow.add_edge("generate_qa_response", "save_memory")  # Merge to save

        # Final Save Step
        workflow.add_edge("save_memory", END)

        return workflow

    # --- Node Execution Functions ---

    def execute_search_memory(self, state: MitreAgentState, config: RunnableConfig):
        """Node to search Mem0 before processing the query."""
        print("--- Executing Node: search_memory ---")
        user_query = state["messages"][-1].content
        user_id = config["configurable"]["user_id"]
        thread_id = config["configurable"]["thread_id"]  # Use as session_id

        memory_context = self._search_memory(
            query=user_query, user_id=user_id, session_id=thread_id
        )

        # Add system message about context finding
        memory_message = SystemMessage(content="Searching for relevant context...")
        if memory_context:
            memory_message = SystemMessage(
                content="Found potentially relevant context from previous interactions."
            )
        else:
            memory_message = SystemMessage(
                content="No specific context found in memory for this query."
            )

        return {
            "user_query": user_query,  # Keep original query separate
            "user_id": user_id,
            "thread_id": thread_id,
            "memory_context": memory_context,  # Store context string or None
            "messages": state["messages"] + [memory_message],  # Add system message
        }

    def execute_classify_intent(self, state: MitreAgentState):
        """Node: Classify the user query intent."""
        print("--- Executing Node: classify_intent ---")
        user_query = state["user_query"]
        memory_context = state.get("memory_context")

        context_str = (
            f"\n\nRelevant context from memory:\n{memory_context}"
            if memory_context
            else ""
        )

        # Robust prompt for classification
        classification_prompt = f"""
        Classify the user's query intent based on the query and context. Choose ONE category:
        1.  **mitre_mapping**: User is asking to identify, map, find, or relate specific cybersecurity activities, scenarios, vulnerabilities, or tool outputs (like logs) to MITRE ATT&CK techniques or tactics. Examples: "Map this log entry to MITRE", "What TTPs are involved in ransomware?", "Find techniques for phishing".
        2.  **general_qa**: User is asking a general cybersecurity question, asking for explanation, advice, definitions, or procedures, NOT specifically requesting a direct mapping to MITRE ATT&CK IDs/names. Examples: "Explain phishing", "How to prevent malware?", "What is CVE-2023-1234?", "What should I do after a breach?".

        User Query: "{user_query}"{context_str}

        Output ONLY the classification label (mitre_mapping or general_qa).
        """
        try:
            response = self.model.invoke(classification_prompt)
            intent = (
                response.content.strip().lower()
                if hasattr(response, "content")
                else str(response).strip().lower()
            )

            if intent not in ["mitre_mapping", "general_qa"]:
                print(
                    f"[Warning] Intent classification returned unexpected value: '{intent}'. Defaulting to general_qa."
                )
                intent = "general_qa"  # Fallback to general Q&A if unsure

            print(f"Classified intent as: {intent}")
            return {"intent": intent}  # Update state with classified intent
        except Exception as e:
            print(
                f"[Error] Intent classification failed: {e}. Defaulting to general_qa."
            )
            return {"intent": "general_qa"}  # Fallback on error

    def route_based_on_intent(
        self, state: MitreAgentState
    ) -> Literal["mitre_mapping", "general_qa", "fallback"]:
        """Function to decide the next node based on classified intent."""
        intent = state.get("intent")
        print(f"--- Routing based on intent: {intent} ---")
        if intent == "mitre_mapping":
            return "mitre_mapping"
        elif intent == "general_qa":
            return "general_qa"
        else:
            # Handle cases where intent might be None or invalid (though execute_classify_intent tries to prevent this)
            print(
                "[Warning] Routing fallback triggered due to missing or invalid intent."
            )
            return "general_qa"

    def execute_retrieve(self, state: MitreAgentState):
        """Node to retrieve techniques based on the original user query."""
        print("--- Executing Node: retrieve_techniques ---")
        user_query = state["user_query"]  # Use the original query for Qdrant
        retrieved_techniques = self._retrieve_attack_techniques(user_query)

        return {
            "retrieved_techniques": retrieved_techniques,
            "messages": state["messages"]
            + [
                AIMessage(
                    content=f"Retrieved {len(retrieved_techniques)} potential techniques. Now processing them."
                )
            ],
        }

    def execute_process_techniques(self, state: MitreAgentState):
        """Node to get details and verify techniques."""
        print("--- Executing Node: process_techniques ---")
        user_query = state["user_query"]
        retrieved_techniques = state["retrieved_techniques"]
        processed_results = []

        if not retrieved_techniques:
            print("No techniques to process.")
            # Store empty list for memory metadata
            self.current_processed_techniques = []
            return {
                "processed_techniques": [],
                "messages": state["messages"]
                + [AIMessage(content="No initial techniques found to process.")],
            }

        print(f"Processing {len(retrieved_techniques)} techniques...")
        for tech_summary in retrieved_techniques:
            # Ensure tech_summary has the technique_id
            tech_id = tech_summary.get("technique_id")  # Direct payload field
            if not tech_id and "metadata" in tech_summary:  # Check metadata
                tech_id = tech_summary["metadata"].get("technique_id")

            if not tech_id:
                print(
                    f"Skipping technique due to missing ID: {tech_summary.get('name', 'N/A')}"
                )
                continue

            details = self._get_technique_details(tech_id)
            if details:
                verification = self._verify_attack_technique(details, user_query)
                processed_results.append(verification)
            else:
                print(
                    f"Could not retrieve details for {tech_id}, skipping verification."
                )
                processed_results.append(
                    {
                        "technique_id": tech_id,
                        "name": tech_summary.get("name"),
                        "match": False,
                        "explanation": "Details not found.",
                        "details_used": tech_summary,
                    }
                )

        # Store processed results on the instance for metadata in add_memory
        self.current_processed_techniques = processed_results
        return {
            "processed_techniques": processed_results,
            "messages": state["messages"]
            + [
                AIMessage(
                    content=f"Finished processing {len(processed_results)} techniques."
                )
            ],
        }

    def execute_generate_report_mitre(self, state: MitreAgentState):
        """Node to generate the final summary report, using memory context."""
        print("--- Executing Node: generate_report ---")
        user_query = state["user_query"]
        processed_techniques = state["processed_techniques"]
        memory_context = state["memory_context"]  # Get context from state

        final_report = self._generate_final_report_mitre(
            user_query, processed_techniques, memory_context
        )
        return {
            "final_report": final_report,
            "messages": state["messages"] + [AIMessage(content=final_report)],
        }

    def execute_generate_qa_response(self, state: MitreAgentState):
        """Node: Generate a response for a general Q&A query."""
        print("--- Executing Node: generate_qa_response ---")
        user_query = state["user_query"]
        memory_context = state.get("memory_context")

        context_str = (
            f"\n\nRelevant context from memory:\n{memory_context}"
            if memory_context
            else ""
        )

        qa_prompt = f"""
        You are a helpful cybersecurity assistant. Answer the user's question clearly and concisely. Use the provided context from memory if it's relevant.

        {context_str}

        User Question: "{user_query}"

        Answer:
        """
        try:
            response = self.model.invoke(qa_prompt)
            answer = response.content if hasattr(response, "content") else str(response)
            print(f"[QA Workflow] Generated QA answer.")
            # Set metadata for memory
            self.current_memory_metadata = {"intent_handled": "general_qa"}
            return {"final_report": answer, "messages": [AIMessage(content=answer)]}
        except Exception as e:
            print(f"[Error] Generating QA response failed: {e}")
            self.current_memory_metadata = {
                "intent_handled": "general_qa",
                "error": True,
            }
            error_message = "I encountered an error trying to answer your question. Please try rephrasing."
            return {
                "final_report": error_message,
                "messages": [AIMessage(content=error_message)],
            }

    def execute_save_memory(self, state: MitreAgentState):
        """Node: Save the interaction (messages + metadata) to Mem0."""
        print("--- Executing Node: save_memory ---")
        user_id = state["user_id"]
        thread_id = state["thread_id"]
        # Combine initial user query + system message + final AI response for context
        messages_to_save = [HumanMessage(content=state["user_query"])] + state[
            "messages"
        ]

        # Metadata was set in the preceding node (process_techniques or generate_qa)
        result = self._add_memory(
            user_id=user_id, session_id=thread_id, messages=messages_to_save
        )
        print(f"Memory save result: {result}")
        # Reset metadata after saving
        self.current_memory_metadata = {}
        return {}  # Final step before END

    def invoke(self, query: str, thread_id: str, user_id: str):
        """Public method to invoke the agent graph."""
        print(f"\n--- Invoking Agent v3 for user: {user_id}, thread: {thread_id} ---")
        # Input to the graph is just the initial messages list
        initial_graph_input = {"messages": [HumanMessage(content=query)]}
        config = {"configurable": {"thread_id": thread_id, "user_id": user_id}}

        # Clear any potential leftover instance metadata
        self.current_memory_metadata = {}

        final_state = self.agent.invoke(initial_graph_input, config=config)

        print("--- Agent Invocation Complete ---")
        final_report = final_state.get(
            "final_report", "Agent finished, but no final report was generated."
        )

        # Clean up just in case
        if hasattr(self, "current_memory_metadata"):
            del self.current_memory_metadata

        return final_report


# --- END OF FILE mitre_agent_refactored.py ---
