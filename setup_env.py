#!/usr/bin/env python3
"""
Cross-platform setup script for bk-ids IDS/IPS system.
Handles OS-specific dependency checks and installation.

Usage:
    python setup_env.py              # Basic setup with checks
    python setup_env.py --venv       # Create virtual environment
    python setup_env.py --help       # Show help
"""

import argparse
import logging
import os
import subprocess
import sys
import winreg
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

# Import platform_utils directly (bypass src/__init__.py to avoid loading heavy dependencies)
# This is necessary because setup_env runs BEFORE dependencies are installed
try:
    # Add src directory to path
    src_path = Path(__file__).parent / 'src'
    sys.path.insert(0, str(src_path))
    
    # Import platform_utils module directly
    import importlib.util
    platform_utils_path = src_path / 'platform_utils.py'
    spec = importlib.util.spec_from_file_location("platform_utils", platform_utils_path)
    platform_utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform_utils)
    
    get_os_type = platform_utils.get_os_type
    is_admin = platform_utils.is_admin
    command_exists = platform_utils.command_exists
except Exception as e:
    logger.error(f"❌ Failed to import platform_utils: {e}")
    logger.error("Make sure src/platform_utils.py exists in the project root.")
    sys.exit(1)

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Define dummy color constants
    class Fore:
        GREEN = ""
        YELLOW = ""
        RED = ""
        BLUE = ""
    class Style:
        BRIGHT = ""
        RESET_ALL = ""


def print_header(text):
    """Print section header."""
    if COLORS_AVAILABLE:
        print(f"\n{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{text}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    else:
        print(f"\n{'=' * 60}")
        print(text)
        print(f"{'=' * 60}")


def print_success(text):
    """Print success message."""
    if COLORS_AVAILABLE:
        print(f"{Fore.GREEN}✓ {text}{Style.RESET_ALL}")
    else:
        print(f"✓ {text}")


def print_warning(text):
    """Print warning message."""
    if COLORS_AVAILABLE:
        print(f"{Fore.YELLOW}⚠ {text}{Style.RESET_ALL}")
    else:
        print(f"⚠ {text}")


def print_error(text):
    """Print error message."""
    if COLORS_AVAILABLE:
        print(f"{Fore.RED}❌ {text}{Style.RESET_ALL}")
    else:
        print(f"❌ {text}")


def print_info(text):
    """Print info message."""
    if COLORS_AVAILABLE:
        print(f"{Fore.BLUE}ℹ {text}{Style.RESET_ALL}")
    else:
        print(f"ℹ {text}")


def check_python_version():
    """
    Check Python version >= 3.8.
    
    Returns:
        bool: True if version >= 3.8, False otherwise
    """
    if sys.version_info < (3, 8):
        print_error(f"Python 3.8+ required, you have {sys.version}")
        return False
    
    version_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print_success(f"Python version: {version_str}")
    return True


def check_libpcap_linux():
    """
    Check libpcap on Linux.
    
    Returns:
        bool: True if libpcap-dev is installed, False otherwise
    """
    if not command_exists('dpkg'):
        print_warning("dpkg not found, skipping libpcap check")
        return False
    
    try:
        result = subprocess.run(
            ['dpkg', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'libpcap-dev' in result.stdout:
            print_success("libpcap-dev installed")
            return True
        else:
            print_warning("libpcap-dev not found")
            print_info("Install with: sudo apt-get install libpcap-dev")
            return False
    
    except subprocess.TimeoutExpired:
        print_warning("dpkg check timed out")
        return False
    except Exception as e:
        print_warning(f"Error checking libpcap: {e}")
        return False


def check_libpcap_macos():
    """
    Check libpcap on macOS (assumed pre-installed).
    
    Returns:
        bool: True (always, assuming pre-installed on macOS 10.6+)
    """
    print_success("libpcap pre-installed on macOS (10.6+)")
    return True


def check_npcap_windows():
    """
    Check Npcap on Windows.
    
    Returns:
        bool: True if Npcap is installed, False otherwise
    """
    npcap_paths = [
        Path("C:/Windows/System32/Npcap"),
        Path("C:/Program Files/Npcap"),
        Path("C:/Program Files (x86)/Npcap"),
    ]
    
    # Check file system paths
    for path in npcap_paths:
        if path.exists():
            print_success(f"Npcap found at: {path}")
            return True
    
    # Check registry (Windows)
    try:
        reg_path = r"SOFTWARE\Npcap"
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        print_success("Npcap registry entry found")
        return True
    except WindowsError:
        pass
    
    # Npcap not found
    print_warning("Npcap not found on this system")
    print_info("Download from: https://nmap.org/npcap/")
    print_info("Required for packet capture on Windows")
    return False


def check_libpcap(skip_checks=False):
    """
    Check libpcap/Npcap availability (OS-specific).
    
    Args:
        skip_checks (bool): If True, skip all checks and return True
    
    Returns:
        bool: True if checks passed or skipped, False if checks failed
    """
    if skip_checks:
        print_info("Skipping OS-specific checks (--skip-checks)")
        return True
    
    os_type = get_os_type()
    
    if os_type == 'linux':
        return check_libpcap_linux()
    elif os_type == 'darwin':
        return check_libpcap_macos()
    elif os_type == 'windows':
        return check_npcap_windows()
    else:
        print_warning(f"Unknown OS type: {os_type}")
        return True


def install_requirements(venv_path=None):
    """
    Install Python requirements from requirements.txt.
    
    If venv_path provided, installs into that virtual environment.
    Otherwise installs globally.
    
    Shows progress during installation for long-running ML library installs.
    
    Args:
        venv_path: Path to virtual environment (optional)
    
    Returns:
        bool: True if successful, False otherwise
    """
    requirements_file = Path(__file__).parent / 'requirements.txt'
    
    if not requirements_file.exists():
        print_error(f"requirements.txt not found at {requirements_file}")
        return False
    
    print_info("Installing Python dependencies from requirements.txt...")
    print_info("This may take 10-30+ minutes (TensorFlow, PyTorch, etc. are large)...")
    print_info("")
    
    try:
        # Determine which pip to use
        if venv_path:
            # Use pip from virtual environment
            os_type = get_os_type()
            if os_type == 'windows':
                pip_executable = venv_path / 'Scripts' / 'pip'
            else:
                pip_executable = venv_path / 'bin' / 'pip'
            
            if not pip_executable.exists():
                print_error(f"pip not found in virtual environment: {pip_executable}")
                return False
        else:
            # Use global pip
            pip_executable = sys.executable.replace('python', 'pip')
            # Fallback: use python -m pip
            pip_executable = sys.executable
        
        # Build command
        if venv_path:
            cmd = [str(pip_executable), 'install', '-r', str(requirements_file)]
        else:
            cmd = [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)]
        
        # Use '-v' for verbose output so users see progress during long ML library installs
        # Increased timeout to 2 hours (7200s) to handle slow internet/machines
        subprocess.run(
            cmd,
            check=True,
            timeout=7200  # 2 hours - ML libraries can take a long time
        )
        print_success("Dependencies installed successfully")
        return True
    
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return False
    except subprocess.TimeoutExpired:
        print_error("Installation timed out (>2 hours)")
        print_warning("If your internet is very slow, you can increase timeout or install manually:")
        if venv_path:
            print_info(f"  {venv_path / ('Scripts' if get_os_type() == 'windows' else 'bin') / 'pip'} install -r {requirements_file}")
        else:
            print_info(f"  pip install -r {requirements_file}")
        return False
    except Exception as e:
        print_error(f"Unexpected error installing dependencies: {e}")
        return False


def create_venv():
    """
    Create virtual environment in ./venv.
    
    Returns:
        bool: True if successful, False otherwise
    """
    venv_path = Path(__file__).parent / 'venv'
    
    print_info("Creating virtual environment...")
    
    try:
        subprocess.run(
            [sys.executable, '-m', 'venv', str(venv_path)],
            check=True,
            timeout=60
        )
        print_success(f"Virtual environment created: ./venv")
        
        # Show activation instructions
        os_type = get_os_type()
        if os_type == 'windows':
            print_info("Activate with: .\\venv\\Scripts\\activate")
        else:
            print_info("Activate with: source venv/bin/activate")
        
        return True
    
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create virtual environment: {e}")
        return False
    except subprocess.TimeoutExpired:
        print_error("Virtual environment creation timed out")
        return False
    except Exception as e:
        print_error(f"Unexpected error creating virtual environment: {e}")
        return False


def main():
    """Main setup routine."""
    parser = argparse.ArgumentParser(
        description="Setup bk-ids IDS/IPS system - Cross-platform setup script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_env.py                # Basic setup (global pip)
  python setup_env.py --venv         # Create venv + install into venv
  python setup_env.py --skip-checks  # Skip OS-specific checks
        """
    )
    
    parser.add_argument(
        '--venv',
        action='store_true',
        help='Create virtual environment (./venv) and install into it'
    )
    parser.add_argument(
        '--skip-checks',
        action='store_true',
        help='Skip OS-specific dependency checks'
    )
    
    args = parser.parse_args()
    
    # Print header
    print_header("bk-ids Setup - Cross-Platform IDS/IPS System")
    
    # Step 1: Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Step 2: Detect OS
    os_type = get_os_type()
    print_success(f"Detected OS: {os_type.capitalize()}")
    
    venv_path = None
    
    # Step 3: Create venv if requested
    if args.venv:
        print()
        venv_path = Path(__file__).parent / 'venv'
        if not create_venv():
            sys.exit(1)
    
    # Step 4: Check libpcap/Npcap (unless skipped)
    print()
    check_libpcap(skip_checks=args.skip_checks)
    
    # Step 5: Install requirements (into venv if created, else globally)
    print()
    if not install_requirements(venv_path=venv_path):
        sys.exit(1)
    
    # Success
    print_header("✓ Setup complete!")
    
    if args.venv:
        print_info("Next steps:")
        if os_type == 'windows':
            print("  1. Activate venv: .\\venv\\Scripts\\activate")
        else:
            print("  1. Activate venv: source venv/bin/activate")
        print("  2. Run the IDS: python main.py --help")
    else:
        print_info("To create virtual environment, run:")
        print("  python setup_env.py --venv")
    
    sys.exit(0)


if __name__ == '__main__':
    main()
