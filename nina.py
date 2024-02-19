#!/usr/bin/env python3

import sys
from nina.lib.colors import warning_message

from nina.nina import main

if sys.version_info.major < 3 or sys.version_info.minor < 9:
    warning_message("Make sure you have Python 3.9+ installed, quitting.")
    sys.exit(1)

if __name__ == "__main__":
    main()