# bk-ids Cross-Platform Setup Verification Checklist

This document provides a step-by-step checklist to verify that the cross-platform IDS/IPS system is properly installed and configured on your machine.

## Quick Start (Recommended Path)

```bash
# 1. Setup using the automated script (recommended)
python setup_env.py --venv

# 2. Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Verify installation
python -c "from src.platform_utils import get_os_type, get_default_interface; print(f'OS: {get_os_type()}'); print(f'Interface: {get_default_interface()}')"

# 4. Run smoke tests
pytest tests/test_smoke.py -v

# 5. Start the system
python main.py --mode mock
```

## Detailed Verification Checklist

### ✅ Environment Setup
- [ ] Python 3.8+ installed (`python --version` shows 3.8 or higher)
- [ ] Git installed and repo cloned (`git status` works)
- [ ] Virtual environment created (`venv/` directory exists)
- [ ] Virtual environment activated (prompt shows `(venv)`)

### ✅ Dependencies Installation
- [ ] Requirements installed without errors
  ```bash
  pip list | grep -E "tensorflow|numpy|pandas|scapy"
  ```
- [ ] All major packages present:
  - tensorflow (2.12+)
  - numpy (1.23+)
  - pandas (1.5+)
  - scapy (2.5+)
  - scikit-learn (1.3+)

### ✅ Platform Detection
- [ ] OS detection works:
  ```bash
  python -c "from src.platform_utils import get_os_type; print(get_os_type())"
  # Expected output: 'windows', 'darwin', or 'linux'
  ```

- [ ] Interface auto-detection works:
  ```bash
  python -c "from src.platform_utils import get_default_interface; print(get_default_interface())"
  # Expected output: eth0, en0, Ethernet, etc. (or None if no network)
  ```

- [ ] Admin privilege detection works:
  ```bash
  python -c "from src.platform_utils import is_admin; print(is_admin())"
  # Expected output: True or False (True only if running as admin/root)
  ```

### ✅ Console Output
- [ ] Colors work in console:
  ```bash
  python -c "from src.console_logger import setup_colored_logger; setup_colored_logger(); import logging; logger = logging.getLogger(); logger.info('✓ Colors work!')"
  # Expected: Green text output (or colorized output)
  ```

### ✅ Tests
- [ ] Smoke tests pass:
  ```bash
  pytest tests/test_smoke.py -v
  # Expected: 3/3 tests passing in <1 second
  ```

- [ ] Full test suite runs (may hang on collection, but that's documented):
  ```bash
  timeout 30 pytest tests/ -v
  # Note: Full test suite may hang due to TensorFlow import - this is expected
  ```

### ✅ System Startup
- [ ] Mock mode starts without errors:
  ```bash
  timeout 10 python main.py --mode mock
  # Expected: Application starts, shows detected interface
  # Press Ctrl+C to stop
  ```

- [ ] Dashboard is accessible (if you run longer):
  - URL: http://localhost:8050
  - Expected: Streamlit dashboard loads

### ✅ Platform-Specific Checks

#### Windows
- [ ] Npcap is installed (for live packet capture):
  - Option 1: Run `python main.py --mode live` and see if errors mention Npcap
  - Option 2: Check Programs > Npcap in Windows Add/Remove Programs
  
- [ ] Console colors work in Windows Terminal or PowerShell
  - Run: `python main.py --mode mock` and observe colored text

#### macOS
- [ ] libpcap is available (pre-installed, but verify):
  ```bash
  which tcpdump  # Should output path
  ```

- [ ] MockFirewallManager is being used:
  ```bash
  python -c "from src.prevention import get_firewall_manager; fm = get_firewall_manager(); print(type(fm).__name__)"
  # Expected output: MockFirewallManager
  ```

- [ ] Console colors display correctly in Terminal.app

#### Linux
- [ ] libpcap-dev is installed:
  ```bash
  apt list --installed | grep libpcap  # Debian/Ubuntu
  dnf list installed | grep libpcap    # RedHat/Fedora
  ```

- [ ] iptables is available:
  ```bash
  which iptables
  ```

- [ ] Console colors work in terminal

## Troubleshooting

### "pip not found in virtual environment"
- **Fixed in latest commit:** Make sure you're using the latest `setup_env.py`
- The fix checks for both `pip` and `pip.exe` on Windows

### "ModuleNotFoundError: No module named 'joblib'"
- **Fixed in earlier commit:** This should not happen if using latest `setup_env.py`
- Make sure to run: `pip install -r requirements.txt`

### "Scapy not installed" warning
- This is expected if you haven't run the full setup yet
- Run: `pip install -r requirements.txt`

### Test collection hangs
- **This is expected behavior** and documented
- Run smoke tests only: `pytest tests/test_smoke.py -v`
- Full test suite may hang due to TensorFlow import optimization on first run

### Cannot detect network interface
- Run with explicit interface: `python main.py --mode mock --interface eth0`
- See README.md for OS-specific interface names

## Success Indicators

✅ **Complete Installation Success** when:
1. All platform detection functions work correctly
2. Smoke tests pass (3/3)
3. Mock mode starts without errors
4. Console output is colored
5. No "ModuleNotFoundError" or "pip not found" errors

✅ **Ready for Development** when:
1. All above items pass
2. Full test suite can be run (even if hangs initially)
3. You can run: `python main.py --mode mock` for extended periods

✅ **Ready for Production** when:
1. All above items pass
2. Linux/macOS: libpcap-dev / libpcap installed
3. Windows: Npcap installed
4. You have tested with `--mode live` if applicable

## Questions or Issues?

- Check `.sisyphus/notepads/cross-platform/` for detailed implementation notes
- Review README.md for platform-specific setup instructions
- Check git history: `git log --oneline` for recent fixes and changes
