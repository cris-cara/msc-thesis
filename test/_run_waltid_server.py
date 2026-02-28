import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]      # .../msc-thesis
PROJECT = ROOT / "project"                      # .../msc-thesis/project

# Assicura che "common" (che sta sotto project/) sia importabile
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(ROOT))

# opzionale: rendi stabile il cwd
os.chdir(str(ROOT))

# Avvia esattamente il modulo che prima lanciavi con "python -m ..."
runpy.run_module("project.alice.mcp.waltid_server", run_name="__main__")