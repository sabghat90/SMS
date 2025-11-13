"""
Secure Messaging System - Client Launcher
Connect to the messaging server from this terminal
"""

import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.network.client import main

main()
