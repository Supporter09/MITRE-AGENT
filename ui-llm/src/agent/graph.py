import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
from langchain.tools import Tool

load_dotenv()

from gpt_researcher import GPTResearcher
import asyncio
from langgraph_supervisor import create_supervisor
from langgraph.store.memory import InMemoryStore
from services.model_loader import load_model
from services.embed_loader import get_embeddings
from agents.web_server_scan_agent import web_server_scan_agent
from agents.vuln_disc_and_exploit_agent import vuln_disc_and_exploit_agent
from agents.scan_agent import scan_network_agent
from resources.resources import gSupervisorPrompt
from langgraph.prebuilt import create_react_agent


# Initialize model and store
use_openai = "OPENAI_API_KEY" in os.environ and bool(os.environ["OPENAI_API_KEY"])
model = load_model(use_openai=use_openai)
store = InMemoryStore(
    index={
        "dims": 1536,
        "embed": get_embeddings(),
    }
)


class WebSearchAgent:
    def __init__(self):
        self.model = load_model()

    async def _search_web(self, query: str):
        """
        Performs web research using GPTResearcher to gather information about a given query.
        """
        try:
            researcher = GPTResearcher(query, "research_report")
            research_result = await researcher.conduct_research()
            report = await researcher.write_report()
            return report if report else "No results found for the query."
        except Exception as e:
            return f"Error during web search: {str(e)}"

    def search_web(self, query: str):
        """
        Synchronous wrapper for the async search function
        """
        try:
            result = asyncio.run(self._search_web(query))
            return result if result else "No results found for the query."
        except Exception as e:
            return f"Error during web search: {str(e)}"

    def create_agent(self):
        web_search_prompt = """You are a web research assistant specialized in cybersecurity information.
Your task is to search the web for relevant information about targets, vulnerabilities, or CTF challenges.
When given a query:
1. Analyze what type of information is needed
2. Use the search_web tool to gather information if it is ctf challenges add keywords challenge writeup to the query for search_web tool
3. Format the results in a clear, organized way
4. Include relevant sources and context
"""
        return create_react_agent(
            model=self.model,
            tools=[
                Tool(
                    name="search_web",
                    func=self.search_web,
                    description="Search the web for information about a target or CTF challenges",
                )
            ],
            name="web_search_expert",
            prompt=web_search_prompt,
        )


# Initialize agents
web_search_agent = WebSearchAgent().create_agent()

# Create supervisor workflow
workflow = create_supervisor(
    [
        web_server_scan_agent,
        vuln_disc_and_exploit_agent,
        scan_network_agent,
        web_search_agent,
    ],
    model=model,
    prompt=gSupervisorPrompt,
    add_handoff_back_messages=True,
    output_mode="full_history",
)

# graph = workflow.compile(store=store)
graph = workflow.compile()
