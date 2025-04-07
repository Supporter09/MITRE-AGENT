# Langchain Multi-Agent System

This repository contains a security multi-agent system built with Langchain.

## Setup

### Environment Setup

1. Create a virtual environment:

```bash
# Using venv
python -m venv venv

# Activate the environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### Install Dependencies

2. Install required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Web UI

To use the web interface:

```bash
streamlit run app.py
```

This will launch a Streamlit application in your browser where you can interact with the multi-agent system.

### Command Line / Code Invocation

To run the agent system directly from code:

1. Edit `main.py` to configure your agents and tasks
2. Run the script:

```bash
python main.py
```

## Features

- Multiple AI agents working together
- Langchain-based workflows
- Web interface for easy interaction
- Customizable agent configurations

