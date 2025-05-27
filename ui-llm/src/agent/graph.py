import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv

load_dotenv()

from langgraph_supervisor import create_supervisor
from langgraph.store.memory import InMemoryStore
from services.model_loader import load_model
from services.embed_loader import get_embeddings
from agents.web_server_scan_agent import web_server_scan_agent
from agents.vuln_disc_and_exploit_agent import vuln_disc_and_exploit_agent
from agents.scan_agent import scan_network_agent
from resources.resources import gSupervisorPrompt

# Initialize model and store
model = load_model()
store = InMemoryStore(
    index={
        "dims": 1536,
        "embed": get_embeddings(),
    }
)

# Create supervisor workflow
workflow = create_supervisor(
    [web_server_scan_agent, vuln_disc_and_exploit_agent, scan_network_agent],
    model=model,
    prompt=gSupervisorPrompt,
    add_handoff_back_messages=True,
    output_mode="full_history",
)

# graph = workflow.compile(store=store)
graph = workflow.compile()

def invoke_supervisor(query):
    messages = [{"role": "user", "content": query}]
    response = graph.invoke({"messages": messages})
    return response
