#!/usr/bin/env python3
"""Thin entrypoint for backward compatibility: ``python pwmanager.py``."""

from __future__ import annotations

import sys

from pwmanager.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)
