from langgraph_supervisor import create_supervisor
from langgraph.store.memory import InMemoryStore
from langchain_ollama import OllamaEmbeddings
from services.model_loader import load_model
from services.embed_loader import get_embeddings
from agents.mitre_agent import MitreAttackAgent
from resources.resources import gSupervisorPrompt

class SupervisorAgent:
    def __init__(self):
        self.model = load_model()
        self.mitre_agent = MitreAttackAgent()
        self.store = InMemoryStore(
            index={
                "dims": 1536,
                "embed": get_embeddings(),
            }
        )

    def create_agent(self):
        workflow = create_supervisor(
            [self.mitre_agent],
            model = self.model,
            name="supervisor_agent",
            prompt=gSupervisorPrompt,
        )

        supervisor = workflow.compile(
            store=self.store
        )

        return supervisor

    def invoke(self, query):
        messages = [{"role": "user", "content": query}]
        response = self.agent.invoke({"messages": messages})
        return response
