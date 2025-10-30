"""
Secure Messaging System - Server Launcher
Start the multi-user messaging server
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.network.server import main

if __name__ == "__main__":
    print("=" * 60)
    print("SECURE MESSAGING SYSTEM - SERVER")
    print("=" * 60)
    print()
    
    main()
