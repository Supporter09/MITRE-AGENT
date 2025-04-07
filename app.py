import streamlit as st
from agents.mitre_agent import MitreAttackAgent

# --- Page Title ---
st.title("🛡️ MITRE ATT&CK Assistant with Memory")

# --- Initialize Agent ---
if "agent" not in st.session_state:
    st.session_state.agent = MitreAttackAgent()

# --- Conversation Context ---
st.sidebar.title("🧠 Conversation Context")
thread_id = st.sidebar.text_input("Thread ID", value=st.session_state.get("thread_id", "default-thread"))
user_id = "default-user"  # Single-user mode for now
st.session_state.thread_id = thread_id  # Persist thread ID

# --- Chat History State ---
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Display Message History ---
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# --- Chat Input ---
if prompt := st.chat_input("Ask anything about MITRE ATT&CK or cybersecurity..."):
    # Show user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Get assistant response
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            response = st.session_state.agent.invoke(
                prompt,
                thread_id=thread_id,
                user_id=user_id
            )

            messages = response.get("messages", [])
            ai_response = None

            for message in messages:
                if getattr(message, "type", None) == "ai":
                    ai_response = message.content
                    st.markdown(ai_response)

            if ai_response:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": ai_response
                })
            else:
                st.markdown("*⚠️ No assistant response was returned.*")
