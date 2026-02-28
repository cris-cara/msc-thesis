import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # .../msc-thesis
PROJECT = ROOT / "project"                  # .../msc-thesis/project

# 1) Path per pytest (processo corrente)
for p in (str(ROOT), str(PROJECT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# 2) Path per i subprocess (server MCP lanciato da mcp_connect)
paths = [str(ROOT), str(PROJECT)]
old = os.environ.get("PYTHONPATH")
if old:
    paths.append(old)

os.environ["PYTHONPATH"] = os.pathsep.join(paths)