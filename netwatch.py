#!/usr/bin/env python3
"""Compatibility wrapper for the former NetWatch entrypoint.

SunsetScan is the new project name. This wrapper keeps old scripts that call
``python3 netwatch.py`` working during the migration period.
"""

import sys

from sunsetscan import SunsetScan, main

NetWatch = SunsetScan


if __name__ == "__main__":
    print(
        "NOTICE: NetWatch has been renamed to SunsetScan. "
        "Use 'python3 sunsetscan.py' going forward.",
        file=sys.stderr,
    )
    sys.exit(main())
