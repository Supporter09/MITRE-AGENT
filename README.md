# Langchain Multi-Agent System

This repository contains a security multi-agent system built with Langchain.

## 🚀 Features

- ✅ Multi-agent architecture powered by Langchain
- 🧠 Support for both local (Ollama) and cloud (OpenAI) LLMs
- 🌐 Streamlit web interface for real-time interactions
- 🧩 Modular and customizable agent workflows
- 📦 Vector database integration via Qdrant
- 📚 MITRE ATT&CK knowledge ingestion and retrieval

## Installation Methods

### Method 1: Docker Installation (Recommended)

1. Install Docker and Docker Compose:

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose
```

2. Run the application:

```bash
docker-compose up
```

3. Access the web interface at `http://localhost:8051`

### Method 2: Local Installation

1. Create and activate virtual environment:

```bash
# Using venv
python -m venv venv

# Activate the environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
streamlit run app.py
```

## Required Tools

The following tools need to be installed if not available:

- nmap: `sudo apt install nmap`
- ffuf: [Install from GitHub](https://github.com/ffuf/ffuf)
- whois: `sudo apt install whois`
- nslookup: `sudo apt install dnsutils`

## Model Setup

### Local Model Setup with Ollama

1. Install Ollama:

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

2. Start Ollama service:

```bash
ollama serve
```

3. Pull required models:

```bash
ollama pull qwen2.5:7b    # For agents
ollama pull nomic-embed-text  # For embedding
```

4. Configure .env:

```bash
OLLAMA_MODEL_NAME=qwen2.5:7b
```

### OpenAI Model Support

1. Create .env file with:

```bash
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL_NAME=gpt-4
```

Note: nomic-embed model from Ollama is still required even when using OpenAI.

## Data Processing

To ingest MITRE ATT&CK data:

1. Place MITRE ATT&CK JSON file (enterprise-attack.json) in working directory
2. Run `qdrant-process.ipynb` notebook
3. Ensure Qdrant is running before processing

## Usage

### Command Line / Code Invocation

1. Edit `main.py` to configure agents and tasks
2. Run:

```bash
python main.py
```
