from agents.supervisor import SupervisorAgent
from utils.print_utils import pretty_print_messages

if __name__ == "__main__":
    # Example pentest scenario (replace with your own target and scope)
    message_history = [{"role": "user", "content": (
        "Perform a penetration test on the target web application at fuff.me. "
        "Enumerate open ports, fingerprint web technologies, and identify vulnerabilities. "
        "Assume we have explicit permission for this assessment."
    )}]

    # Initialize the supervisor
    supervisor = SupervisorAgent()
    # Create the orchestrating agent
    supervisor_agent = supervisor.create_agent()

    # Run the pentest scenario
    print("\n--- Supervisor Pentest Demo ---\n")
    while True:
        for chunk in supervisor_agent.stream(
            {"messages": [{"role": "user", "content": message_history}]}
        ):
            pretty_print_messages(chunk)

        user_query = input("User prompt: ")
        if user_query.lower() in ["exit", "quit"]:
            print("Exiting...")
            break
        else:
            message_history.append({"role": "user", "content": user_query})

