#!/usr/bin/env python3
"""Check changes to tests and merge-blocking CI coverage without building code."""

from test_inventory.cli import main


if __name__ == '__main__':
    raise SystemExit(main())
