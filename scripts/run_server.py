"""
Secure Messaging System - Server Launcher
Start the multi-user messaging server
"""

import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.network.server import main

print("=" * 60)
print("SECURE MESSAGING SYSTEM - SERVER")
print("=" * 60)
print()

main()
