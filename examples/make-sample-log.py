#!/usr/bin/env python3
"""Write a log to look at.

Nothing here comes from a real machine. An auth.log carries usernames, source
addresses and sometimes hostnames, so one copied from a lived-in system is not
something to commit or hand around. Every line this writes is assembled from the
builder the tests use, in the shapes sshd, sudo and useradd actually produce, so
the report can be exercised without a log that belongs to someone.

Usage: make-sample-log.py [auth.log]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "tests"))

import log_builder as build  # noqa: E402


def sample():
    """Three addresses: one that gets in, one that scans, one that belongs there."""
    return build.brute_force_log() + build.scanner_log() + build.quiet_log()


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("".join(sample()))
    print(f"wrote {target}")
    print(f"read it with: python3 -m authlogsessions {target}")


if __name__ == "__main__":
    main()
