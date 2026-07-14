"""Shared test fixtures and setup."""
import os
import sys

# Ensure we're running from the server directory
server_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if server_dir not in sys.path:
    sys.path.insert(0, server_dir)

# Ensure required directories exist
os.makedirs(os.path.join(server_dir, "app", "keys"), exist_ok=True)
os.makedirs(os.path.join(server_dir, "evidence_store"), exist_ok=True)
os.makedirs(os.path.join(server_dir, "config"), exist_ok=True)
