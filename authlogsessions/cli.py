"""Command line entry point.

Read the logs, rebuild the sessions, print the report. The work is in the
modules this calls.
"""

import argparse
import json
import sys

from . import __version__
from . import parse
from . import report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="authlog-sessions",
        description="Rebuild attacker sessions from Linux authentication logs.")
    parser.add_argument("logs", nargs="+",
                        help="auth.log, secure, or a journal export, gzipped or not")
    parser.add_argument("-n", "--top", type=int, default=10,
                        help="sources to print in full (default: 10)")
    parser.add_argument("--source", metavar="ADDRESS",
                        help="print only this source address")
    parser.add_argument("--year", type=int,
                        help="year for logs that do not carry one, as syslog does not")
    parser.add_argument("--json", action="store_true",
                        help="print the reconstruction as JSON")
    parser.add_argument("--version", action="version",
                        version=f"authlog-sessions {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.top < 1:
        print("authlog-sessions: --top has to be at least 1", file=sys.stderr)
        return 2

    events = []
    lines = 0
    files = []
    host = None

    try:
        for path, _, line in parse.read_lines(args.logs, year=args.year):
            lines += 1
            if path not in files:
                files.append(path)
            event = parse.parse_line(line, year=args.year)
            if event is None:
                continue
            if not host and event.host:
                host = event.host
            events.append(event)
    except FileNotFoundError as error:
        print(f"authlog-sessions: no such file: {error.filename}", file=sys.stderr)
        return 2
    except IsADirectoryError as error:
        print(f"authlog-sessions: that is a directory: {error.filename}", file=sys.stderr)
        return 2
    except PermissionError as error:
        print(f"authlog-sessions: not allowed to read {error.filename}", file=sys.stderr)
        return 2

    if not events:
        print("authlog-sessions: nothing in those files looked like a log line",
              file=sys.stderr)
        return 1

    result = report.Report(events, files, lines, host=host)

    if args.json:
        print(json.dumps(report.as_dict(result, top=args.top), indent=2))
    else:
        print(report.render(result, top=args.top, focus=args.source), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
