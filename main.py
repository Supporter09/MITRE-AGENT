from agents.mitre_agent import MitreAttackAgent

mitre_agent = MitreAttackAgent()
query = "An employee reported receiving an email with an attachment that claims to be an invoice. The attachment is an Excel file with macros."
response = mitre_agent.invoke(query, 'default-thread', 'ball')
