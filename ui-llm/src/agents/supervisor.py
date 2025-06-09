import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv

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

async def search_web_tool(query: str, report_type: str):
    """
    Performs web research using GPTResearcher to gather information about a given query.

    Args:
        query (str): The search query to research
        report_type (str): Type of report to generate (e.g. 'research_report')

    Returns:
        tuple: Contains:
            - report (str): The generated research report
            - research_context (dict): Context information from the research
            - research_costs (dict): Cost information for the research
            - research_sources (list): List of sources used in research
    """
    researcher = GPTResearcher(query, report_type)
    research_result = await researcher.conduct_research()
    report = await researcher.write_report()

    # Get additional information
    research_context = researcher.get_research_context()
    research_costs = researcher.get_costs()
    research_sources = researcher.get_research_sources()

    return report, research_context, research_costs, research_sources

class SupervisorAgent:
    def __init__(self):
        self.model = load_model()
        self.store = InMemoryStore(
            index={
                "dims": 1536,
                "embed": get_embeddings(),
            }
        )

    def create_agent(self):
        workflow = create_supervisor(
            [web_server_scan_agent, vuln_disc_and_exploit_agent, scan_network_agent, search_web_tool],
            model=self.model,
            prompt=gSupervisorPrompt,
            add_handoff_back_messages=True,
            output_mode="full_history",
        )

        supervisor = workflow.compile(store=self.store)

        return supervisor

    def invoke(self, query):
        messages = [{"role": "user", "content": query}]
        response = self.agent.invoke({"messages": messages})
        return response
