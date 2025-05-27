import os
import re
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langchain.tools import Tool
from langgraph.prebuilt import create_react_agent
from langgraph.store.memory import InMemoryStore
from qdrant_client import QdrantClient
from services.embed_loader import get_embeddings
from services.semgrep_service import query_semgrep_rules
from utils.utils import clean_text
from typing import Dict, Any, List


class VulnerabilityFixingAgent:
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
        os.environ["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")

        # Qdrant client for accessing vulnerability rules
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

    def detect_code_in_prompt(self, prompt):
        """Detect if the prompt contains code based on code block markers or code indicators."""
        # Check for code blocks with triple backticks
        if re.search(r"```[\w]*\n[\s\S]*?\n```", prompt):
            return True
            
        # Check for common code patterns
        code_indicators = [
            r"\bfunction\s+\w+\s*\(",  # function declarations
            r"\bclass\s+\w+",          # class declarations
            r"\bif\s*\(.*\)\s*\{",     # if statements with braces
            r"\bfor\s*\(.*\)\s*\{",    # for loops with braces
            r"\bwhile\s*\(.*\)\s*\{",  # while loops with braces
            r"=\s*new\s+\w+",          # new object instantiation
            r"#include",               # C/C++ include
            r"import\s+[\w.]+",        # import statements
            r"<\?php",                 # PHP opening tag
            r"def\s+\w+\s*\(.*\):",    # Python function definition
            r"SELECT\s+.*\s+FROM",     # SQL query
            r"\w+\s+=\s+\w+\.",        # variable assignment with dot notation
            r"\bvar\s+\w+\s*=",        # JavaScript var
            r"\blet\s+\w+\s*=",        # JavaScript let
            r"\bconst\s+\w+\s*="       # JavaScript const
        ]
        
        for pattern in code_indicators:
            if re.search(pattern, prompt, re.IGNORECASE):
                return True
                
        return False

    def extract_code_from_prompt(self, prompt):
        """Extract code blocks from a prompt."""
        # Try to extract code blocks with triple backticks
        code_blocks = re.findall(r"```(?:\w+)?\n([\s\S]*?)\n```", prompt)
        if code_blocks:
            return "\n".join(code_blocks)
            
        # If no backtick code blocks found, and we detected code, treat the entire prompt as code
        if self.detect_code_in_prompt(prompt):
            return prompt
            
        return None

    def find_vulnerabilities(self, code):
        """Tool to find vulnerabilities in code using Semgrep rules."""
        if not code:
            return "No code provided to analyze."
            
        potential_vulnerabilities = query_semgrep_rules(code, client=self.qdrant_client)
        
        if not potential_vulnerabilities:
            return "No vulnerabilities detected in the provided code."
        
        result = "Potential vulnerabilities found:\n\n"
        for i, vuln in enumerate(potential_vulnerabilities, 1):
            result += f"{i}. Rule: {vuln['rule_id']}\n"
            result += f"   Description: {vuln['message']}\n"
            result += f"   Fix Suggestion: {vuln['fix_suggestion']}\n\n"
        
        return result

    def fix_code(self, code, vulnerabilities):
        """Tool to fix code based on identified vulnerabilities."""
        prompt = f"""
        You are a security-focused code analyst. Fix the following code by addressing the identified vulnerabilities.
        
        Original code:
        ```
        {code}
        ```
        
        Identified vulnerabilities:
        {vulnerabilities}
        
        Provide the complete fixed code with a brief explanation of what was changed and why.
        Make sure your fix directly addresses the security concerns mentioned in the vulnerability descriptions.
        """
        
        response = self.model.invoke(prompt)
        return response.content

    def handle_query(self, query):
        """Tool to handle general security and vulnerability questions."""
        prompt = f"""
        You are a cybersecurity expert specializing in code vulnerabilities and secure coding practices.
        Answer the following question in a helpful, educational manner:
        
        Question: {query}
        
        In your response:
        1. Be clear and concise
        2. If applicable, mention specific types of vulnerabilities
        3. Provide actionable advice for secure coding
        4. Include examples if they would help illustrate your points
        """
        
        response = self.model.invoke(prompt)
        return response.content

    def create_agent(self):
        """Create the vulnerability fixing agent with the defined tools"""
        vuln_agent_prompt = """You are an expert in code security and vulnerability analysis.

Your job is to help users understand code vulnerabilities and fix security issues in their code.

When presented with user input:
1. Determine if the input contains code or is a general security question
2. For general questions, use handle_query to provide a helpful answer
3. For code analysis:
   a. Use find_vulnerabilities to identify security issues
   b. If vulnerabilities are found, use fix_code to generate a secure version

Keep your responses conversational and educational. When explaining fixes:
- Clearly explain what vulnerabilities were found
- Show how they were fixed
- Explain why the new code is more secure

You're like a friendly security mentor who helps users write more secure code.
"""

        return create_react_agent(
            model=self.model,
            tools=[
                self.find_vulnerabilities,
                self.fix_code,
                self.handle_query,
            ],
            name="vulnerability_expert",
            prompt=vuln_agent_prompt,
        )

    def invoke(self, prompt, thread_id="default-thread", user_id="default-user"):
        """Public method to invoke the agent with a prompt"""
        # Process the input to check if it contains code
        code = self.extract_code_from_prompt(prompt)
        
        # Create the appropriate messages based on input
        if code:
            messages = [{"role": "user", "content": f"Please analyze this code for vulnerabilities:\n\n```\n{code}\n```"}]
        else:
            messages = [{"role": "user", "content": prompt}]
            
        return self.agent.invoke(
            {"messages": messages},
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "user_id": user_id,
                }
            },
        )