"""
Secure Messaging System - Standalone Mode Launcher
Run the standalone single-user messaging system
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import main

if __name__ == "__main__":
    main()
