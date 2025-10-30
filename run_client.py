"""
Secure Messaging System - Client Launcher
Connect to the messaging server from this terminal
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.network.client import main

if __name__ == "__main__":
    main()
