"""
Smart Contract Vulnerability Analysis Agent.

Modules:
    llm_client  – Ollama LLM wrapper with retry logic and streaming
    schemas     – Pydantic models for structured vulnerability output
    chunker     – Solidity code pre-processing (line numbering, chunking)
    json_extract– Robust JSON extraction from noisy LLM responses
    agent       – High-level analysis orchestrator
    main        – CLI entry point
"""
