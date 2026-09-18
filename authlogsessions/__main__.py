"""Run it with python3 -m authlogsessions, which is how the readme calls it."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
