"""Make `core`, `utils`, etc. importable in tests regardless of the cwd
pytest is invoked from (repo root or backend/)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
