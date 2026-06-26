
@echo off
setlocal enabledelayedexpansion
 
echo ============================================
echo  Red Team Agent - Full Setup Script
echo  Using Python 3.11 explicitly
echo ============================================
echo.
 
REM ── Python 3.11 path ─────────────────────────────────
set PY311=C:\Users\rihem\AppData\Local\Programs\Python\Python311\python.exe
 
REM ── Verify Python 3.11 exists ────────────────────────
if not exist "%PY311%" (
    echo ERROR: Python 3.11 not found at %PY311%
    echo Please verify your Python 3.11 installation path.
    pause
    exit /b 1
)
 
echo [OK] Python 3.11 found:
%PY311% --version
echo.
 
REM ── Create .env file if it doesn't exist ─────────────
if not exist ".env" (
    echo [1/7] Creating .env file...
    (
        echo # ── LLM API Keys ───────────────────────────────────────
        echo GROQ_API_KEY=your_groq_api_key_here
        echo.
        echo # ── Models ─────────────────────────────────────────────
        echo GROQ_MODEL_HEAVY=llama-3.3-70b-versatile
        echo GROQ_MODEL_FAST=qwen-qwq-32b
        echo LOCAL_MODEL=qwen
        echo EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
        echo.
        echo # ── Qdrant ─────────────────────────────────────────────
        echo QDRANT_HOST=localhost
        echo QDRANT_PORT=6333
        echo QDRANT_PATH=./qdrant
        echo.
        echo # ── Neo4j ──────────────────────────────────────────────
        echo NEO4J_URI=bolt://localhost:7687
        echo NEO4J_USER=neo4j
        echo NEO4J_PASSWORD=your_neo4j_password_here
        echo.
        echo # ── NVD API ────────────────────────────────────────────
        echo NVD_API_KEY=your_nvd_api_key_here
        echo.
        echo # ── Campaign defaults ──────────────────────────────────
        echo STEALTH_LEVEL=high
        echo MAX_THREADS=4
        echo LOG_LEVEL=INFO
        echo REPORTS_DIR=./reports
        echo TARGET_ENV=medflow
    ) > .env
    echo [OK] .env created. Edit it and add your GROQ_API_KEY.
) else (
    echo [1/7] .env already exists, skipping.
)
echo.
 
REM ── Upgrade pip for 3.11 ─────────────────────────────
echo [2/7] Upgrading pip for Python 3.11...
%PY311% -m pip install --upgrade pip --quiet
echo [OK] pip upgraded.
echo.
 
REM ── Core utilities ───────────────────────────────────
echo [3/7] Installing core utilities...
%PY311% -m pip install ^
    groq ^
    litellm ^
    python-dotenv ^
    pydantic ^
    rich ^
    loguru ^
    tenacity ^
    requests ^
    aiohttp ^
    tqdm ^
    pyyaml ^
    numpy ^
    pandas ^
    --quiet
echo [OK] Core utilities installed.
echo.
 
REM ── Vector store ─────────────────────────────────────
echo [4/7] Installing vector store...
%PY311% -m pip install ^
    "qdrant-client>=1.13.2" ^
    "sentence-transformers>=3.4.1" ^
    --quiet
echo [OK] Vector store installed.
echo.
 
REM ── Agent frameworks (require Python 3.10-3.13) ──────
echo [5/7] Installing agent frameworks...
%PY311% -m pip install ^
    "agno>=2.6.0" ^
    "crewai>=1.14.0" ^
    "crewai-tools>=0.47.0" ^
    "autogen-agentchat>=0.7.5" ^
    --quiet
echo [OK] Agent frameworks installed.
echo.
 
REM ── Knowledge and memory ─────────────────────────────
echo [6/7] Installing knowledge and memory layers...
%PY311% -m pip install ^
    "neo4j>=5.28.0" ^
    "letta-client>=1.12.0" ^
    stix2 ^
    taxii2-client ^
    python-nmap ^
    --quiet
echo [OK] Knowledge and memory layers installed.
echo.
 
REM ── Verify all imports ───────────────────────────────
echo [7/7] Verifying all imports...
echo.
 
%PY311% -c "import groq; print('  groq              OK')"
%PY311% -c "import litellm; print('  litellm           OK')"
%PY311% -c "import qdrant_client; print('  qdrant_client     OK')"
%PY311% -c "import sentence_transformers; print('  sentence_transf.  OK')"
%PY311% -c "import agno; print('  agno              OK')"
%PY311% -c "import crewai; print('  crewai            OK')"
%PY311% -c "import autogen; print('  autogen           OK')"
%PY311% -c "import neo4j; print('  neo4j             OK')"
%PY311% -c "import letta_client; print('  letta_client      OK')"
%PY311% -c "import loguru; print('  loguru            OK')"
%PY311% -c "import rich; print('  rich              OK')"
%PY311% -c "import dotenv; print('  dotenv            OK')"
%PY311% -c "import nmap; print('  nmap              OK')"
%PY311% -c "import stix2; print('  stix2             OK')"
echo.
 
REM ── Create run.bat for easy launching ────────────────
echo Creating run.bat for easy launching...
(
    echo @echo off
    echo REM Always runs with Python 3.11
    echo set PY311=C:\Users\rihem\AppData\Local\Programs\Python\Python311\python.exe
    echo %%PY311%% main.py %%*
) > run.bat
echo [OK] run.bat created.
echo.
 
echo ============================================
echo  Setup complete!
echo.
echo  NEXT STEPS:
echo  1. Open .env and replace:
echo       GROQ_API_KEY=your_groq_api_key_here
echo     with your real Groq API key from:
echo       https://console.groq.com/keys
echo.
echo  2. Run the agent with:
echo       run.bat --target 192.168.1.50
echo     or:
echo       run.bat --target medflow.local
echo ============================================
pause
