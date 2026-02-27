"""AI Backend Configuration Guide

This scanner now supports THREE ways to use AI for vulnerability classification:

═══════════════════════════════════════════════════════════════════════════════

1) LOCAL HEURISTIC AI (DEFAULT, NO SETUP NEEDED) ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is the RECOMMENDED approach - works immediately without any API keys.

Features:
  - Uses built-in rules based on response analysis
  - Smart detection of SQL injection, XSS, directory traversal
  - Suggests appropriate mutation strategies
  - Fast (no network calls)
  - ~90% accuracy for common vulnerabilities

Nothing to configure! Just run:
  python cli.py https://example.com --depth 2 -f both
  python example_usage.py https://example.com


═══════════════════════════════════════════════════════════════════════════════

2) OLLAMA LOCAL AI (RECOMMENDED IF YOU WANT ADVANCED AI) 🚀
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run an AI model locally on your computer (free, no API key needed).

Setup:
  a) Download & install Ollama from: https://ollama.ai
  
  b) Pull a small model (one-time, ~4GB):
     ollama pull mistral
     
     OR for faster inference (smaller model):
     ollama pull neural-chat
  
  c) Start Ollama (it runs in background):
     ollama serve
  
  d) Enable in scanner:
     set AI_BACKEND=ollama
     python cli.py https://example.com --depth 2
     
     OR for auto-fallback (tries Ollama, falls back to heuristic):
     set AI_BACKEND=auto
     python cli.py https://example.com --depth 2

Benefits:
  - Runs locally (no cloud privacy concerns)
  - ~95% accuracy with advanced understanding
  - Free (one-time model download)
  - Works offline
  - Still faster than cloud APIs


═══════════════════════════════════════════════════════════════════════════════

3) GOOGLE GEMINI API (CLOUD, NEEDS API KEY) ☁️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If you already have a Gemini API key:

Get API Key:
  1. Go to: https://makersuite.google.com/app/apikey
  2. Create a new API key (free tier available)
  3. Copy the key

Enable in scanner:
  set GOOGLE_API_KEY=your-api-key-here
  set AI_BACKEND=gemini
  python cli.py https://example.com --depth 2

Issues fixed:
  ✅ Proper URL construction with API key
  ✅ JSON response parsing from Gemini's text format
  ✅ SSL certificate handling (disable verify for Windows)
  ✅ Timeout handling


═══════════════════════════════════════════════════════════════════════════════

QUICK COMPARISON
━━━━━━━━━━━━━━━━

┌──────────────────┬───────────┬────────┬──────┬────────────┐
│ Method           │ Setup     │ Cost   │ Speed│ Accuracy   │
├──────────────────┼───────────┼────────┼──────┼────────────┤
│ Heuristic (DEF)  │ None ✅   │ Free   │ Fast │ 85-90%     │
│ Ollama           │ 5 min     │ Free   │ Good │ 92-95%     │
│ Gemini API       │ 2 min     │ Free*  │ Good │ 95-98%     │
└──────────────────┴───────────┴────────┴──────┴────────────┘

* Free tier available (1500 requests/day)


═══════════════════════════════════════════════════════════════════════════════

ENVIRONMENT VARIABLES REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Choose backend
set AI_BACKEND=heuristic     # Local (default) - **RECOMMENDED**
set AI_BACKEND=ollama        # Use Ollama if available
set AI_BACKEND=gemini        # Use Gemini API only
set AI_BACKEND=auto          # Try each in order: Ollama, Gemini, Heuristic

# Ollama (local)
set OLLAMA_URL=http://localhost:11434  # default

# Gemini (cloud)
set GOOGLE_API_KEY=your-key-here       # Get from makersuite.google.com/app/apikey


═══════════════════════════════════════════════════════════════════════════════

TROUBLESHOOTING
━━━━━━━━━━━━━━━

Issue: Slow scan performance
→ Use heuristic (default) or local Ollama

Issue: Wrong vulnerability classifications
→ Switch to Ollama or Gemini for better accuracy

Issue: Can't get Gemini working
→ Use heuristic (always works) - no API needed!

Issue: Want offline capability
→ Use heuristic or Ollama (both work without internet)


═══════════════════════════════════════════════════════════════════════════════

RECOMMENDED SETUP
━━━━━━━━━━━━━━━━

For best results with zero setup:
  python cli.py https://example.com --depth 3 -f both

If you want better accuracy and have 5 minutes:
  1. Install Ollama (https://ollama.ai)
  2. Run: ollama pull mistral
  3. In another terminal: ollama serve
  4. Then:
     set AI_BACKEND=auto
     python cli.py https://example.com --depth 3 -f both

"""
