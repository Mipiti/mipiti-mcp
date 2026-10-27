"""Add the current tool catalog to catalog_history.json (catalog.py)."""

import sys

from .catalog import main

if __name__ == "__main__":
    sys.exit(main(sys.argv))
