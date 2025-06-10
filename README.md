# Langchain Multi-Agent System

This repository contains a security multi-agent system built with Langchain.

---

## 🚀 Features

- ✅ Multi-agent architecture powered by Langchain
- 🧠 Support for both local (Ollama) and cloud (OpenAI) LLMs
- 🌐 Streamlit web interface for real-time interactions
- 🧩 Modular and customizable agent workflows
- 📦 Vector database integration via Qdrant
- 📚 MITRE ATT&CK knowledge ingestion and retrieval

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

### Tools need to install

- Docker and Docker Compose

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose
```

- nmap

```bash
sudo apt install nmap
```

- [ffuf](https://github.com/ffuf/ffuf)
- whois

```bash
sudo apt install whois
```

- nslookup

```bash
sudo apt install dnsutils
```

### Local Model Setup with Ollama

This project supports running local LLMs and embedding models via [Ollama](https://ollama.com/), an easy-to-use tool for managing and running models locally.

#### 1. Install Ollama

Follow the instructions for your OS from the [official website](https://ollama.com/download), or use the appropriate command below:

##### On macOS:

```bash
brew install ollama
```

##### On Linux:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### 2. Start the Ollama service

```bash
ollama serve
```

#### 3. Pull local modals:

```bash
ollama pull qwen:2.5-7b # For agents

ollama pull nomic-embed-text # For embedding
```

Ensure your .env configuration reflects:

```bash
# .env
OLLAMA_MODEL_NAME=qwen:2.5-7b
```

### OpenAI Model Support

- This system supports both local models via Ollama and cloud models via OpenAI.

- Create a .env file in the root directory and add the following:

- However, you still need to install nomic embed model from Ollama to use with this project

```
# Cloud model via OpenAI
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL_NAME=gpt-4
```

## Usage

### Data Processing with Qdrant

To ingest MITRE ATT&CK data and store embeddings into Qdrant:

1. Prepare Input

- Download and place a MITRE ATT&CK JSON file (e.g., enterprise-attack.json) in your working directory.

2. Process and Save to Qdrant

- Run the notebook:

```
qdrant-process.ipynb
```

- The notebook will:
  - Parse the MITRE data
  - Generate embeddings
  - Store them in the connected Qdrant vector store
  - Ensure Qdrant is running and accessible before processing the data.

### Web UI

To use the web interface:

#### Option 1: Using Docker Compose (Recommended)

```bash
docker-compose up
```

Then open your browser and navigate to `http://localhost:8051`

#### Option 2: Direct Run

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
