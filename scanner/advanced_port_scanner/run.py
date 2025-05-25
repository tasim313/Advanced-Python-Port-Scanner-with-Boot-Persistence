#!/usr/bin/env python3
"""
Advanced Port Scanner Launcher
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    base_dir = Path(__file__).parent
    venv_dir = base_dir / "venv"
    
    # Check if virtual environment exists
    if not venv_dir.exists():
        print("Virtual environment not found. Please run setup first.")
        return
        
    # Activate virtual environment and start Flask app
    if sys.platform.startswith('win'):
        python_path = venv_dir / "Scripts" / "python.exe"
    else:
        python_path = venv_dir / "bin" / "python"
        
    app_path = base_dir / "web_interface" / "app.py"
    
    print("Starting Advanced Port Scanner...")
    print("Web interface will be available at: http://localhost:5558")
    print("Press Ctrl+C to stop")
    
    try:
        subprocess.run([str(python_path), str(app_path)], cwd=str(base_dir))
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    main()
