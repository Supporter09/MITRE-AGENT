from dotenv import load_dotenv

load_dotenv()
import os
import json
import subprocess
import re
import logging
import sys
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import convert_to_messages

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Constants ---
MAX_TOOL_RETRIES = 3
DEFAULT_NMAP_FLAGS = "-p- -v -t -T5"

# --- Core Utilities ---


def run_cli_command(
    command: str, timeout: int = 180
) -> str:  # Increased timeout for Nmap
    """
    Executes a shell command and returns its output or an error message.
    """
    try:
        logger.info(f"Executing CLI: {command}")
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Handle non-zero exit codes gracefully
        )
        if process.returncode == 0:
            # Some tools might print to stderr for informational messages,
            # but if returncode is 0, we primarily care about stdout.
            # However, nmap sometimes prints useful info to stderr even on success.
            # For simplicity now, we'll stick to stdout on success.
            # If a command specifically needs stderr too, this could be adjusted.
            return process.stdout.strip()
        else:
            # Combine stdout and stderr for more context on errors
            output = (process.stdout.strip() + "\n" + process.stderr.strip()).strip()
            # Nmap might return non-zero if e.g. host is down but -Pn is not used,
            # or other specific nmap errors.
            return f"Error (code {process.returncode}): {output}"
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {command}")
        return f"Error: Command timed out after {timeout}s."
    except Exception as e:
        logger.error(f"Error executing command '{command}': {e}")
        return f"Error: Exception - {e}"


# --- Simplified Tool Functions ---


def run_whois(domain: str) -> str:
    """Performs a WHOIS lookup on a domain."""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain for WHOIS."
    # Sanitize domain input slightly to prevent command injection if used directly,
    # though run_cli_command with shell=True needs careful command construction.
    # For simple domain names, this is generally okay.
    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain for WHOIS."
    return run_cli_command(f"whois {safe_domain}")


def run_nslookup(domain: str) -> str:
    """Performs DNS enumeration for a domain."""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain for NSLOOKUP."
    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain for NSLOOKUP."
    return run_cli_command(f"nslookup {safe_domain}")


def run_nmap(target: str) -> str:
    """Discovers open ports, services, OS, and versions on a target using Nmap."""
    if not target or not isinstance(target, str):
        return "Error: Invalid target for NMAP."
    # Target can be domain or IP, nmap handles it. Basic sanitization.
    safe_target = re.sub(r"[^a-zA-Z0-9.-]", "", target)
    if not safe_target:
        return "Error: Invalid characters in target for NMAP."
    return run_cli_command(f"nmap {DEFAULT_NMAP_FLAGS} {safe_target} | grep open")


def pretty_print_message(message, indent=False):
    pretty_message = message.pretty_repr(html=True)
    if not indent:
        print(pretty_message)
        return

    indented = "\n".join("\t" + c for c in pretty_message.split("\n"))
    print(indented)


def pretty_print_messages(update, last_message=False):
    is_subgraph = False
    if isinstance(update, tuple):
        ns, update = update
        # Skip parent graph updates
        if len(ns) == 0:
            return

        graph_id = ns[-1].split(":")[0]
        print(f"Update from subgraph {graph_id}")
        print("-" * 80)
        is_subgraph = True

    for node_name, node_update in update.items():
        update_label = f"Update from node {node_name}:"
        if is_subgraph:
            update_label = "\t" + update_label

        print(update_label)
        print()

        messages = convert_to_messages(node_update["messages"])
        if last_message:
            messages = messages[-1:]

        for m in messages:
            pretty_print_message(m, indent=is_subgraph)

        print()


def setup_model(use_openai: bool = False):
    if use_openai and os.environ.get("OPENAI_API_KEY"):
        model_name = os.getenv("OPENAI_MODEL_NAME", "gpt-4o")
        logger.info(f"Using OpenAI model: {model_name}")
        return ChatOpenAI(
            api_key=os.environ.get("OPENAI_API_KEY"),
            model=model_name,
            temperature=0.1,
            streaming=True,
        )
    else:
        model_name = os.getenv("OLLAMA_MODEL_NAME", "qwen2.5:7b")
        logger.info(f"Using Ollama model: {model_name} from http://localhost:11434")
        return ChatOllama(
            model=model_name,
            temperature=0.1,
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )

# use_openai = "OPENAI_API_KEY" in os.environ and bool(os.environ["OPENAI_API_KEY"])
model = setup_model(use_openai=False)

scan_network_agent = create_react_agent(
    model=model,
    tools=[run_whois, run_nslookup, run_nmap],
    prompt="""
        You are a network security expert performing reconnaissance on a target domain or IP address.

        Available tools:
        - run_whois: Get domain registration and ownership info
        - run_nslookup: Get DNS records and nameserver info
        - run_nmap: Scan for open ports and running services

        Instructions:
        1. Use each tool to gather information about the target
        2. If a tool fails 3 times, skip it and continue with other tools
        3. Format your final findings as a dictionary with these keys:
           - whois_info: Domain registration details
           - dns_info: DNS records and nameservers
           - open_ports: List of open ports and services
           - errors: Any tools that failed or were skipped

        Be thorough but efficient in your scanning. Focus on identifying potential security-relevant information.
        """,
    name="Scan Network Agent",
)

# --- Example Usage ---
if __name__ == "__main__":
    # Example target (replace with your own)
    target = "lms.hust.edu.vn"

    # Prepare the input for the agent
    input_data = {"input": target}

    # Run the agent and get the result
    # result = scan_network_agent.invoke(input_data)

    # Pretty print the result
    print("\n--- Results ---")
    for chunk in scan_network_agent.stream({"messages": [{"role": "user", "content": f"Scan the target {target}"}]}):
        pretty_print_messages(chunk)
