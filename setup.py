#!/usr/bin/env python3
"""
Setup and Verification Script for Secure Messaging System
Checks dependencies, runs tests, and verifies installation
"""

import sys
import os
import subprocess

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_section(text):
    """Print formatted section"""
    print(f"\n[{text}]")

def check_python_version():
    """Check if Python version is 3.7+"""
    print_section("Checking Python Version")
    version = sys.version_info
    print(f"Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ Python 3.7+ required!")
        return False
    
    print("✓ Python version OK")
    return True

def check_dependencies():
    """Check if required packages are installed"""
    print_section("Checking Dependencies")
    
    required = ['cryptography']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"✓ {package} installed")
        except ImportError:
            print(f"✗ {package} NOT installed")
            missing.append(package)
    
    if missing:
        print(f"\n❌ Missing packages: {', '.join(missing)}")
        print("   Run: pip install -r requirements.txt")
        return False
    
    print("✓ All dependencies installed")
    return True

def check_directory_structure():
    """Verify directory structure"""
    print_section("Checking Directory Structure")
    
    required_dirs = [
        'src/core',
        'src/network',
        'scripts',
        'tests',
        'examples',
        'docs/guides',
        'docs/api'
    ]
    
    all_exist = True
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✓ {directory}/")
        else:
            print(f"✗ {directory}/ NOT FOUND")
            all_exist = False
    
    return all_exist

def check_core_modules():
    """Check if core modules can be imported"""
    print_section("Checking Core Modules")
    
    modules = [
        'src.core.authentication',
        'src.core.blockchain',
        'src.core.classical_ciphers',
        'src.core.modern_ciphers',
        'src.core.hashing',
        'src.core.elgamal',
        'src.core.crypto_math',
        'src.core.storage'
    ]
    
    all_ok = True
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module.split('.')[-1]}.py")
        except Exception as e:
            print(f"✗ {module.split('.')[-1]}.py - {str(e)}")
            all_ok = False
    
    return all_ok

def run_quick_tests():
    """Run quick verification tests"""
    print_section("Running Quick Tests")
    
    try:
        # Test storage
        from src.core.storage import SecureStorage
        storage = SecureStorage(data_dir="test_setup_data")
        print("✓ Storage module working")
        
        # Test authentication
        from src.core.authentication import UserAuthentication
        auth = UserAuthentication(storage=storage)
        print("✓ Authentication module working")
        
        # Test blockchain
        from src.core.blockchain import MessageBlockchain
        blockchain = MessageBlockchain(difficulty=1, storage=storage)
        print("✓ Blockchain module working")
        
        # Test ciphers
        from src.core.classical_ciphers import CaesarCipher
        cipher = CaesarCipher()
        print("✓ Classical ciphers working")
        
        from src.core.modern_ciphers import XORStreamCipher
        xor = XORStreamCipher()
        print("✓ Modern ciphers working")
        
        # Test ElGamal
        from src.core.elgamal import ElGamal
        keys = ElGamal.generate_keys(bits=8)
        print("✓ ElGamal working")
        
        # Cleanup
        import shutil
        if os.path.exists("test_setup_data"):
            shutil.rmtree("test_setup_data")
        
        print("✓ All quick tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {str(e)}")
        return False

def show_next_steps():
    """Show next steps for user"""
    print_header("Setup Complete!")
    
    print("\n🎉 Your Secure Messaging System is ready!")
    
    print("\n📌 Next Steps:\n")
    print("1. Run in Network Mode:")
    print("   Terminal 1: python scripts/run_server.py")
    print("   Terminal 2: python scripts/run_client.py")
    
    print("\n2. Or run in Standalone Mode:")
    print("   python scripts/run_standalone.py")
    
    print("\n3. Run Tests:")
    print("   python tests/run_tests.py")
    
    print("\n4. View Documentation:")
    print("   See docs/INDEX.md for complete documentation")
    
    print("\n5. Try Examples:")
    print("   python examples/demo_storage.py")
    print("   python examples/verify_fix.py")
    
    print("\n📚 Documentation:")
    print("   - Quick Start: docs/guides/QUICKSTART.md")
    print("   - Network Guide: docs/guides/NETWORK_GUIDE.md")
    print("   - Storage Guide: docs/guides/STORAGE.md")
    print("   - Full Index: docs/INDEX.md")

def main():
    """Main setup verification"""
    print_header("Secure Messaging System - Setup & Verification")
    
    # Change to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Directory Structure", check_directory_structure),
        ("Core Modules", check_core_modules),
        ("Quick Tests", run_quick_tests)
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ Error in {name}: {str(e)}")
            results.append((name, False))
    
    # Summary
    print_section("Summary")
    all_passed = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:10} - {name}")
        if not result:
            all_passed = False
    
    if all_passed:
        show_next_steps()
        return 0
    else:
        print("\n❌ Setup incomplete. Please fix the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
