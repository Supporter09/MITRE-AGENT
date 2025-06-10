import streamlit as st
import json
import os
import re
import uuid
import ast
from langchain_core.messages import (
    convert_to_openai_messages,
    AIMessage,
    HumanMessage,
)
from langchain_core.messages import convert_to_messages

from agents.mitre_agent_refactored import MitreAttackAgent
from agents.vuln_agent import VulnerabilityFixingAgent

# --- Configuration ---
HISTORY_DIR = "chat_history"
DEFAULT_THREAD_ID = "chat_0"
DEFAULT_SUPERVISOR_THREAD_ID = "supervisor_chat_0"
DEFAULT_USER_ID = "default-user"

# --- Ensure History Directory Exists ---
os.makedirs(HISTORY_DIR, exist_ok=True)

# --- Helper Functions for History ---


def sanitize_filename(filename):
    """Removes potentially problematic characters for filenames."""
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.replace(" ", "_")
    if not sanitized or sanitized.strip(".") == "":
        return f"invalid_thread_{hash(filename)}"
    return sanitized


def get_history_filepath(thread_id):
    """Constructs the full path for a thread's history file."""
    return os.path.join(HISTORY_DIR, f"{sanitize_filename(thread_id)}.json")


def load_chat_history(thread_id):
    """Loads chat history from a JSON file for a given thread ID."""
    filepath = get_history_filepath(thread_id)
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                history = json.load(f)
                if isinstance(history, list) and all(
                    isinstance(msg, dict) and "role" in msg and "content" in msg
                    for msg in history
                ):
                    return history
                else:
                    print(
                        f"Warning: Invalid format found in {filepath}. Starting fresh."
                    )
                    return []
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON from {filepath}. Starting fresh.")
            return []
        except Exception as e:
            print(f"Error loading history for thread '{thread_id}': {e}")
            return []
    return []


def save_chat_history(thread_id, messages):
    """Saves chat history to a JSON file."""
    filepath = get_history_filepath(thread_id)
    try:
        with open(filepath, "w") as f:
            json.dump(messages, f, indent=2)
    except Exception as e:
        print(f"Error saving history for thread '{thread_id}': {e}")


# --- Page Title ---
st.title("🛡️ Security Assistant")

# --- Tab Selection ---
tab1, tab2, tab3 = st.tabs(
    [
        "MITRE ATT&CK Assistant",
        "Vulnerability Fixing",
        "Supervisor Agent",
    ]
)

# --- Initialize Agents ---
if "mitre_agent" not in st.session_state:
    try:
        st.session_state.mitre_agent = MitreAttackAgent()
    except Exception as e:
        st.error(f"Failed to initialize MITRE Agent: {e}")
        st.stop()

if "vuln_agent" not in st.session_state:
    st.session_state.vuln_agent = VulnerabilityFixingAgent()

# --- Supervisor Agent ---
if "supervisor_agent" not in st.session_state:
    from agents.supervisor import SupervisorAgent

    st.session_state.supervisor_agent = SupervisorAgent()
    st.session_state.supervisor = st.session_state.supervisor_agent.create_agent()

# --- Initialize Chat Histories Structure (Once per session) ---
if "chat_histories" not in st.session_state:
    st.session_state.chat_histories = {}
if "supervisor_histories" not in st.session_state:
    st.session_state.supervisor_histories = {}

# --- Initialize current_thread_id if not set ---
if "current_thread_id" not in st.session_state:
    st.session_state.current_thread_id = DEFAULT_THREAD_ID
if "current_supervisor_thread_id" not in st.session_state:
    st.session_state.current_supervisor_thread_id = DEFAULT_SUPERVISOR_THREAD_ID

# --- Sidebar for Context and Thread Selection ---
with st.sidebar:
    st.title("💬 Conversation")

    # **** New Chat Button ****
    if st.button("✨ New Chat", use_container_width=True):
        new_thread_id = f"chat_{uuid.uuid4()}"  # Generate unique ID
        st.session_state.current_thread_id = new_thread_id
        # Ensure history entry exists for the new thread (will be empty)
        st.session_state.chat_histories[new_thread_id] = []

        st.success(f"Started new chat: {new_thread_id}")
        # Rerun to reflect the new thread ID in the input box and clear chat area
        st.rerun()

    if st.button("✨ New Supervisor Chat", use_container_width=True):
        new_thread_id = f"supervisor_chat_{uuid.uuid4()}"  # Generate unique ID
        st.session_state.current_supervisor_thread_id = new_thread_id
        # Ensure history entry exists for the new thread (will be empty)
        st.session_state.supervisor_histories[new_thread_id] = []

        st.success(f"Started new supervisor chat: {new_thread_id}")
        # Rerun to reflect the new thread ID in the input box and clear chat area
        st.rerun()

    st.markdown("---")

    try:
        history_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")]
        # Sort files by modification time, newest first
        history_files.sort(
            key=lambda f: os.path.getmtime(os.path.join(HISTORY_DIR, f)), reverse=True
        )

        if not history_files:
            st.caption("No past conversations found.")
        else:
            # Split and display regular chat histories
            st.subheader("MITRE Chats")
            for filename in history_files:
                if filename.startswith("chat_"):
                    thread_id_from_file = filename[:-5]  # Remove .json extension
                    display_name = thread_id_from_file
                    if st.button(
                        display_name,
                        key=f"history_{thread_id_from_file}",
                        use_container_width=True,
                    ):
                        if st.session_state.current_thread_id != thread_id_from_file:
                            st.session_state.current_thread_id = thread_id_from_file
                            st.rerun()

            # Split and display supervisor chat histories
            st.subheader("Supervisor Chats")
            for filename in history_files:
                if filename.startswith("supervisor_chat_"):
                    thread_id_from_file = filename[:-5]  # Remove .json extension
                    display_name = thread_id_from_file
                    if st.button(
                        display_name,
                        key=f"history_{thread_id_from_file}",
                        use_container_width=True,
                    ):
                        if (
                            st.session_state.current_supervisor_thread_id
                            != thread_id_from_file
                        ):
                            st.session_state.current_supervisor_thread_id = (
                                thread_id_from_file
                            )
                            st.rerun()

    except FileNotFoundError:
        st.error(f"History directory not found: {HISTORY_DIR}")
    except Exception as e:
        st.error(f"Error listing history files: {e}")

    st.markdown("---")

    st.write(f"User ID: `{DEFAULT_USER_ID}`")


# --- Load History for the Current Thread ---
active_thread_id = st.session_state.current_thread_id
if active_thread_id not in st.session_state.chat_histories:
    print(f"Loading history for thread: {active_thread_id}")
    st.session_state.chat_histories[active_thread_id] = load_chat_history(
        active_thread_id
    )

current_messages = st.session_state.chat_histories.get(active_thread_id, [])

# --- MITRE ATT&CK Tab ---
with tab1:
    # Header inside the tab
    st.header(f"MITRE ATT&CK Assistant")
    st.caption(f"Conversation Thread: `{active_thread_id}`")

    message_container = st.container(height=500, border=False)

    # Display existing messages within the container
    with message_container:
        if not current_messages:
            st.info("Start the conversation by typing below.")
        for msg in current_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    # Chat input: Positioned after the message container in the code flow
    mitre_prompt = st.chat_input(
        "Ask about MITRE ATT&CK, scenarios, or general cybersecurity...",
        key=f"mitre_input_{active_thread_id}",  # Unique key per thread
    )

    # --- Handle Input ---
    if mitre_prompt:
        # 1. Append and save user message
        user_message = {"role": "user", "content": mitre_prompt}
        current_messages.append(user_message)
        save_chat_history(active_thread_id, current_messages)

        # 2. *Immediately* display user message in the container
        with message_container:
            with st.chat_message("user"):
                st.markdown(mitre_prompt)

        # 3. Get assistant response
        assistant_message_content = "*Thinking...*"  # Placeholder
        with message_container:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    if "mitre_agent" in st.session_state:
                        try:
                            response = st.session_state.mitre_agent.invoke(
                                mitre_prompt,
                                thread_id=active_thread_id,
                                user_id=DEFAULT_USER_ID,
                            )
                            print(
                                f"Agent response for thread '{active_thread_id}': {response[:100]}..."
                            )
                            assistant_message_content = (
                                response if response else "*No response generated.*"
                            )

                        except Exception as e:
                            st.error(f"An error occurred: {e}")
                            print(f"Agent invocation error: {e}")
                            assistant_message_content = f"Sorry, an error occurred: {e}"
                    else:
                        st.error("MITRE Agent is not initialized.")
                        assistant_message_content = "Agent not available."

        # 4. Append and save assistant message *after* it's generated and displayed
        assistant_message = {"role": "assistant", "content": assistant_message_content}
        current_messages.append(assistant_message)
        save_chat_history(active_thread_id, current_messages)

        st.rerun()  # Rerun to refresh the chat display


# --- Vulnerability Fixing Tab ---
with tab2:
    st.header("Vulnerability Fixing Assistant")
    st.markdown(
        """
    Chat with me about code vulnerabilities. Share your code snippets and I'll help identify and fix security issues.
    I can also explain general vulnerability concepts and best practices.
    """
    )

    # --- Chat History State for Vuln Fixing ---
    if "vuln_messages" not in st.session_state:
        st.session_state.vuln_messages = []

    # --- Display Message History ---
    for msg in st.session_state.vuln_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # --- Chat Input ---
    vuln_prompt = st.chat_input(
        "Ask about vulnerabilities or share code to analyze...", key="vuln_input"
    )
    if vuln_prompt:
        # Show user message
        st.session_state.vuln_messages.append({"role": "user", "content": vuln_prompt})
        with st.chat_message("user"):
            st.markdown(vuln_prompt)

        # Get assistant response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                # Use active_thread_id and DEFAULT_USER_ID defined earlier
                response = st.session_state.vuln_agent.invoke(
                    vuln_prompt, thread_id=active_thread_id, user_id=DEFAULT_USER_ID
                )

                messages = response.get("messages", [])
                ai_response = None

                for message in messages:
                    if getattr(message, "type", None) == "ai":
                        ai_response = message.content
                        st.markdown(ai_response)

                if ai_response:
                    st.session_state.vuln_messages.append(
                        {"role": "assistant", "content": ai_response}
                    )
                else:
                    st.markdown("*⚠️ No analysis response was returned.*")

# --- Supervisor Tab ---
with tab3:
    st.header("Supervisor Agent")
    st.caption(
        f"Conversation Thread: `{st.session_state.current_supervisor_thread_id}`"
    )

    # Load supervisor chat history
    supervisor_thread_id = st.session_state.current_supervisor_thread_id
    if supervisor_thread_id not in st.session_state.supervisor_histories:
        st.session_state.supervisor_histories[supervisor_thread_id] = load_chat_history(
            supervisor_thread_id
        )
    supervisor_messages = st.session_state.supervisor_histories[supervisor_thread_id]

    message_container = st.container(height=500, border=False)
    with message_container:
        if not supervisor_messages:
            st.info("Start the supervisor conversation by typing below.")
        for msg in supervisor_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    supervisor_prompt = st.chat_input(
        "Ask the supervisor agent for help...",
        key=f"supervisor_input_{supervisor_thread_id}",
    )

    if supervisor_prompt:
        # 1. Append and save user message
        user_message = {"role": "user", "content": supervisor_prompt}
        supervisor_messages.append(user_message)
        save_chat_history(supervisor_thread_id, supervisor_messages)

        with message_container:
            with st.chat_message("user"):
                st.markdown(supervisor_prompt)

        # 2. Get supervisor response
        with message_container:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    try:
                        config = {"configurable": {"thread_id": supervisor_thread_id}}

                        response = st.session_state.supervisor.stream(
                            {"messages": supervisor_messages}, config
                        )
                        for chunk in response:
                            for node_name, node_update in chunk.items():
                                update_label = f"Update from node {node_name}:"
                                print(update_label)
                                print()

                                messages = convert_to_openai_messages(
                                    node_update["messages"]
                                )

                                # Only append the last assistant message
                                for m in messages:
                                    print(m)

                                assistant_messages = [
                                    msg
                                    for msg in messages
                                    if msg.get("role") == "assistant"
                                    and msg.get("content")
                                    and msg.get("name") == "supervisor"
                                    and not msg.get("content").startswith(
                                        "Transferring"
                                    )
                                ]
                                if assistant_messages:
                                    last_message = assistant_messages[-1]
                                    st.markdown(last_message["content"])
                                    supervisor_messages.append(last_message)
                                    save_chat_history(
                                        supervisor_thread_id, supervisor_messages
                                    )
                    except Exception as e:
                        st.error(f"Supervisor agent error: {e}")
                        error_message = {"role": "assistant", "content": f"Error: {e}"}
                        supervisor_messages.append(error_message)
                        save_chat_history(supervisor_thread_id, supervisor_messages)

        st.rerun()
