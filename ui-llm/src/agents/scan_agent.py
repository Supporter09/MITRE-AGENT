import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv()

import json
import subprocess
import re
import logging
import sys
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from services.model_loader import load_model
from utils.print_utils import pretty_print_messages

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Constants ---
MAX_TOOL_RETRIES = 3
DEFAULT_NMAP_FLAGS = "-p- -v -T5"

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


use_openai = "OPENAI_API_KEY" in os.environ and bool(os.environ["OPENAI_API_KEY"])
model = load_model(use_openai=False)

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
        If you are not able to find any information, just say "No information found"
        Summarize the findings in a json format for other agents to use
        """,
    name="Scan Network Agent",
)

# --- Example Usage ---
if __name__ == "__main__":
    # Example target (replace with your own)
    target = "206.189.33.53"

    # Prepare the input for the agent
    input_data = {"input": target}

    # Run the agent and get the result
    # result = scan_network_agent.invoke(input_data)

    # Pretty print the result
    print("\n--- Results ---")
    for chunk in scan_network_agent.stream(
        {"messages": [{"role": "user", "content": f"Scan the target {target}"}]}
    ):
        pretty_print_messages(chunk)
