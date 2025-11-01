"""
Secure Messaging System - Standalone Mode Launcher
Run the standalone single-user messaging system
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from main import main

main()
