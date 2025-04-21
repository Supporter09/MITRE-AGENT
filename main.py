# from agents.mitre_agent import MitreAttackAgent

# mitre_agent = MitreAttackAgent()
# query = "An employee reported receiving an email with an attachment that claims to be an invoice. The attachment is an Excel file with macros."
# response = mitre_agent.invoke(query, 'default-thread', 'ball')


from agents.mitre_agent_refactored import MitreAttackAgent
from dotenv import load_dotenv
import os
load_dotenv()

required_vars = ["QDRANT_URL", "QDRANT_API_KEY", "MEM0_API_KEY"] # MEM0_API_KEY is now essential
if not all(os.getenv(var) for var in required_vars):
    print(f"Error: Missing one or more environment variables: {', '.join(required_vars)}")
    # Check which specific vars are missing if needed
    for var in required_vars:
            if not os.getenv(var): print(f"Missing: {var}")
    exit(1)

# use_openai_flag = bool(os.getenv("OPENAI_API_KEY"))
use_openai_flag = False
agent_instance = MitreAttackAgent(use_openai=use_openai_flag)

test_query = "An attacker gained access using phishing, installed malware persistence via registry run keys, and exfiltrated data to a C2 server."
test_thread_id = "mitre_session_002"
test_user_id = "analyst_beta"

# --- Test Case 1: MITRE Mapping Query ---
mitre_query = "Map the following scenario to MITRE: An attacker used PowerShell (T1059.001) for execution after gaining access via phishing (T1566)."
print(f"\n--- Test Case 1: MITRE Mapping ---")
result1 = agent_instance.invoke(mitre_query, test_thread_id, test_user_id)
print("\n--- Final Agent Result 1 (MITRE) ---")
print(result1)

# --- Test Case 2: General Q&A Query ---
qa_query = "Can you explain what spearphishing is and give some prevention tips?"
print(f"\n--- Test Case 2: General Q&A ---")
# Use the same thread_id to test memory context carry-over
result2 = agent_instance.invoke(qa_query, test_thread_id, test_user_id)
print("\n--- Final Agent Result 2 (Q&A) ---")
print(result2)

# --- Test Case 3: Another MITRE Query in same session ---
mitre_query_2 = "What MITRE technique involves Windows Management Instrumentation (WMI)?"
print(f"\n--- Test Case 3: Follow-up MITRE Mapping ---")
result3 = agent_instance.invoke(mitre_query_2, test_thread_id, test_user_id)
print("\n--- Final Agent Result 3 (MITRE) ---")
print(result3)

# Example of searching memory explicitly (if needed for debugging/testing)
print("\n--- Explicit Memory Search ---")
search_results = agent_instance._search_memory(query="gained access using phishing", user_id=test_user_id, session_id=test_thread_id)
print(search_results)
