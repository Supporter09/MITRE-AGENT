import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv

load_dotenv()


from gpt_researcher import GPTResearcher
import asyncio

async def get_report(query: str, report_type: str):
    researcher = GPTResearcher(query, report_type)
    research_result = await researcher.conduct_research()
    report = await researcher.write_report()

    # Get additional information
    research_context = researcher.get_research_context()
    research_costs = researcher.get_costs()
    research_sources = researcher.get_research_sources()

    return report, research_context, research_costs, research_sources

if __name__ == "__main__":
    query = "picoCTF SSTI1 challenge writeup"
    report_type = "research_report"

    report, context, costs, sources = asyncio.run(get_report(query, report_type))

    print("Report:")
    print(report)
    print("\nResearch Costs:")
    print(costs)
    print("\nNumber of Research Sources:")
    print(len(sources))
