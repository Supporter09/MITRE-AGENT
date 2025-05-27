import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv()


import json
import subprocess
import re
import logging
import webtech
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from utils.print_utils import pretty_print_messages
from services.model_loader import load_model


# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Constants ---
MAX_TOOL_RETRIES = 3
DEFAULT_NMAP_FLAGS = "-p- -v -T5"
PATH_TO_WORDLIST = "~/wordlists"
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
def find_directories(domain: str) -> str:
    """Finds directories on a web server."""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain for ffuf."

    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain for ffuf."
    return run_cli_command(f"ffuf -u {target} -w {PATH_TO_WORDLIST}/common.txt")


def find_subdomains(domain: str) -> str:
    """Finds subdomains on a web server."""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain for ffuf to find subdomains."

    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain for ffuf to find subdomains."
    return run_cli_command(
        f"ffuf -u {target} -w {PATH_TO_WORDLIST}/subdomains-top1million-110000.txt"
    )


def check_webtech(domain: str) -> str:
    """Checks website technologies on a web server. HTTP/HTTPS or File is required"""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain to check webtech."

    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain for webtech."

    wt = webtech.WebTech(options={"json": True})
    return wt.start_from_url(domain)


# This method should be instruct so llm will take a look to filter web name to a list
def check_headers(domain: str) -> str:
    """Checks headers on a web server."""
    if not domain or not isinstance(domain, str):
        return "Error: Invalid domain to check headers."

    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    if not safe_domain:
        return "Error: Invalid characters in domain to check headers."
    return run_cli_command(f"curl -I {target}")


# use_openai = "OPENAI_API_KEY" in os.environ and bool(os.environ["OPENAI_API_KEY"])
model = load_model(use_openai=False)


# This agent should server if port 80/443/8080 is open which is the most common port for web servers
web_server_scan_agent = create_react_agent(
    model=model,
    tools=[find_directories, find_subdomains, check_webtech, check_headers],
    prompt="""
        You are a web security expert performing reconnaissance on a target website.

        Available tools:
        - find_directories: Discover hidden directories and files
        - find_subdomains: Enumerate subdomains
        - check_webtech: Identify web technologies and frameworks. HTTP/HTTPS or File is required
        - check_headers: Analyze HTTP response headers

        Instructions:
        1. Use each tool systematically to gather information about the target website
        2. If a tool fails 3 times, skip it and continue with other tools
        3. Format your final findings as a JSON object with these keys:
           - directories: List of discovered directories and files
           - subdomains: List of enumerated subdomains
           - technologies: Web technologies, frameworks and versions detected
           - headers: Security-relevant HTTP headers
           - errors: Any tools that failed or were skipped

        Process the data carefully and provide structured JSON output that can be consumed by other agents.
        Focus on identifying potential security weaknesses and attack surfaces.
        """,
    name="Web Server Scan Agent",
)

# --- Example Usage ---
if __name__ == "__main__":
    # Example target (replace with your own)
    target = "http://ffuf.me"

    # Prepare the input for the agent
    input_data = {"input": target}

    # Run the agent and get the result
    # result = scan_network_agent.invoke(input_data)

    # Pretty print the result
    print("\n--- Results ---")
    for chunk in web_server_scan_agent.stream(
        {"messages": [{"role": "user", "content": f"Scan the target {target}"}]}
    ):
        pretty_print_messages(chunk)
