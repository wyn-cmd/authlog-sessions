"""Reading log lines into events.

Two timestamp shapes turn up in practice and both are handled here. A syslog
line starts with the month, day and time and carries no year, which is a real
problem for a file whose entries span a new year, so the year comes from a
flag, from the file's own modification time, or from today. A journal export
starts with a full ISO 8601 stamp and needs no guessing.

Everything else is pattern matching against the handful of message shapes sshd,
sudo and the account tools actually write. A line that matches nothing is kept
as an unknown event rather than dropped, because counting what a parser could
not read is how you find out the parser is wrong.
"""

import datetime
import re

from collections import namedtuple

# The actions worth telling apart. Anything the patterns below do not recognise
# lands in UNKNOWN and shows up in the summary, which is a signal that the log
# has a shape this tool has not seen yet.
FAILED_PASSWORD = "failed password"
INVALID_USER = "invalid user"
PAM_FAILURE = "pam authentication failure"
MAX_ATTEMPTS = "maximum attempts exceeded"
ACCEPTED_PASSWORD = "accepted password"
ACCEPTED_KEY = "accepted publickey"
SESSION_OPENED = "session opened"
SESSION_CLOSED = "session closed"
DISCONNECTED = "disconnected"
CLOSED = "connection closed"
SUDO_COMMAND = "sudo command"
REFUSED = "refused by configuration"
ACCOUNT_CHANGE = "account change"
UNKNOWN = "unrecognised"

Event = namedtuple("Event", "timestamp host source action user address port detail")
Event.__doc__ = """One line of the log, in the shape the rest of the tool wants."""

ISO_STAMP = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
SYSLOG_STAMP = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# The process name and its pid, as in sshd[1234]: or sudo: or useradd[99]:
PROCESS = re.compile(r"(?P<source>[A-Za-z][A-Za-z0-9_.-]*)(?:\[(?P<pid>\d+)\])?:\s*")

ADDRESS = re.compile(r"\b(?P<address>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,39}:[0-9a-fA-F:]{2,39})\b")
PORT = re.compile(r"\bport\s+(?P<port>\d{1,5})\b")

MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

# A username in a log line is either after "for", or in a key=value pair as in
# user=root. The first form is what sshd uses most of the time.
USER_AFTER_FOR = re.compile(r"\bfor (?:invalid user )?(?P<user>[\w.$@-]+)")
USER_PAIR = re.compile(r"\buser=(?P<user>[\w.$@-]*)")

# Account tooling, which is what you look for after a successful break-in.
ACCOUNT_PATTERNS = (
    (re.compile(r"\bnew user:\s*name=(?P<user>[\w.$@-]+)"), "user added"),
    (re.compile(r"\buser (?:modified|changed):\s*name=(?P<user>[\w.$@-]+)"), "user modified"),
    (re.compile(r"\b(?:delete|remove) user\b.*?name=(?P<user>[\w.$@-]+)"), "user removed"),
    (re.compile(r"\bgroup added:\s*name=(?P<user>[\w.-]+)"), "group added"),
    (re.compile(r"\bpassword changed for (?P<user>[\w.$@-]+)"), "password changed"),
)

SSHD_PATTERNS = (
    (re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<address>\S+) port (?P<port>\d+)"), FAILED_PASSWORD),
    (re.compile(r"Failed password for (?:illegal user )?(?P<user>\S+) from (?P<address>\S+) port (?P<port>\d+)"), FAILED_PASSWORD),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<address>\S+)"), INVALID_USER),
    # A refusal is not a wrong password. The account exists and the
    # server is configured to reject it, which reads differently.
    (re.compile(r"User (?P<user>\S+) not allowed because"), REFUSED),
    (re.compile(r"Failed none for invalid user (?P<user>\S+) from "
                r"(?P<address>\S+) port (?P<port>\d+)"), FAILED_PASSWORD),
    (re.compile(r"Accepted password for (?P<user>\S+) from (?P<address>\S+) port (?P<port>\d+)"), ACCEPTED_PASSWORD),
    # A keyboard interactive login is a password prompt in disguise, and
    # some servers are configured to offer only that.
    (re.compile(r"Accepted keyboard-interactive/pam for (?P<user>\S+) from "
                r"(?P<address>\S+) port (?P<port>\d+)"), ACCEPTED_PASSWORD),
    (re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<address>\S+) port (?P<port>\d+)"), ACCEPTED_KEY),
    (re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<address>\S+) port (?P<port>\d+)"), MAX_ATTEMPTS),
    (re.compile(r"Received disconnect from (?P<address>\S+) port (?P<port>\d+)"), DISCONNECTED),
    (re.compile(r"Disconnected from (?:invalid |authenticating )?user (?P<user>\S+) (?P<address>\S+) port (?P<port>\d+)"), DISCONNECTED),
    (re.compile(r"Connection closed by (?:authenticating |invalid )?user (?P<user>\S+) (?P<address>\S+) port (?P<port>\d+)"), CLOSED),
    (re.compile(r"Connection closed by (?P<address>\S+) port (?P<port>\d+)"), CLOSED),
    (re.compile(r"Connection reset by (?P<address>\S+) port (?P<port>\d+)"), CLOSED),
    (re.compile(r"Timeout before authentication for (?P<address>\S+) "
                r"port (?P<port>\d+)"), CLOSED),
    (re.compile(r"session opened for user (?P<user>[\w.$@-]+)"), SESSION_OPENED),
    (re.compile(r"session closed for user (?P<user>[\w.$@-]+)"), SESSION_CLOSED),
    (re.compile(r"pam_unix\(sshd:auth\): authentication failure"), PAM_FAILURE),
    (re.compile(r"PAM \d+ more authentication failure"), PAM_FAILURE),
    # OpenSSH 8 moved the session lines out of pam and into sshd itself,
    # so a newer machine writes these and no pam line at all.
    (re.compile(r"Starting session \d+ of user (?P<user>\S+) from "
                r"(?P<address>\S+) port (?P<port>\d+)"), SESSION_OPENED),
    (re.compile(r"Close session: user (?P<user>\S+) from "
                r"(?P<address>\S+) port (?P<port>\d+)"), SESSION_CLOSED),
)

SUDO_PATTERN = re.compile(
    r"^\s*(?P<user>[\w.$@-]+)\s*:\s*(?:TTY=(?P<tty>\S+)\s*;\s*)?.*?COMMAND=(?P<command>.+)$")


def parse_stamp(text, year=None, fallback_year=None):
    """A timestamp from either log format, or None if there is not one."""
    match = ISO_STAMP.match(text)
    if match:
        raw = match.group("stamp").replace("Z", "+00:00")
        try:
            return datetime.datetime.fromisoformat(raw)
        except ValueError:
            return None

    match = SYSLOG_STAMP.match(text)
    if match:
        parts = match.group("stamp").split()
        month = MONTHS.get(parts[0])
        if not month:
            return None
        chosen = year or fallback_year or datetime.date.today().year
        try:
            return datetime.datetime(chosen, month, int(parts[1]),
                                     int(parts[2][:2]), int(parts[2][3:5]),
                                     int(parts[2][6:8]))
        except ValueError:
            return None
    return None


def strip_stamp(text):
    """The line without its timestamp, so the patterns start at the process."""
    match = ISO_STAMP.match(text) or SYSLOG_STAMP.match(text)
    if match:
        return text[match.end():].strip()
    return text.strip()


def find_address(text):
    match = ADDRESS.search(text)
    if not match:
        return None
    address = match.group("address")
    # The colon-heavy branch of the address pattern can swallow a bare word, so
    # anything without a digit is not an address.
    if not any(character.isdigit() for character in address):
        return None
    return address


def find_port(text):
    match = PORT.search(text)
    return int(match.group("port")) if match else None


def find_user(text):
    match = USER_AFTER_FOR.search(text)
    if match:
        return match.group("user")
    match = USER_PAIR.search(text)
    if match and match.group("user"):
        return match.group("user")
    return None


class YearTracker:
    """The year for syslog lines, which carry a month and nothing more.

    For a log that spans New Year the month going backwards between two
    lines is the giveaway, and the year follows it. Without this every
    line after the turn reads as the previous year, which puts the end of
    an incident before its beginning in the report.
    """

    def __init__(self, year=None):
        self.year = year or datetime.date.today().year
        self.previous_month = None

    def for_line(self, line):
        match = SYSLOG_STAMP.match(line)
        if not match:
            return self.year
        month = MONTHS.get(match.group("stamp").split()[0])
        if not month:
            return self.year
        if self.previous_month and month < self.previous_month:
            self.year += 1
        self.previous_month = month
        return self.year


def parse_line(line, year=None, fallback_year=None):
    """One log line into an Event, or None when there is nothing to read."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    stamp = parse_stamp(line, year=year, fallback_year=fallback_year)
    body = strip_stamp(line)

    process = PROCESS.search(body)
    if not process:
        return None
    source = process.group("source")
    message = body[process.end():]

    host = body[:process.start()].strip().split(" ")[0] if process.start() else ""

    address = find_address(message)
    port = find_port(message)

    # sudo writes the account first, then the command. It is worth its own pass
    # because the interesting part is the command line, not the login.
    if source in ("sudo", "su"):
        match = SUDO_PATTERN.match(message)
        if match:
            return Event(stamp, host, source, SUDO_COMMAND, match.group("user"),
                         address, port, match.group("command").strip())

    if source in ("useradd", "usermod", "userdel", "groupadd", "groupmod",
                  "groupdel", "passwd", "chpasswd"):
        for pattern, described in ACCOUNT_PATTERNS:
            match = pattern.search(message)
            if match:
                return Event(stamp, host, source, ACCOUNT_CHANGE, match.group("user"),
                             address, port, described)
        return Event(stamp, host, source, ACCOUNT_CHANGE, find_user(message),
                     address, port, message.strip())

    for pattern, action in SSHD_PATTERNS:
        match = pattern.search(message)
        if match:
            groups = match.groupdict()
            return Event(stamp, host, source, action,
                         groups.get("user") or find_user(message),
                         groups.get("address") or address,
                         int(groups["port"]) if groups.get("port") else port,
                         message.strip())

    return Event(stamp, host, source, UNKNOWN, find_user(message), address, port,
                 message.strip())


def read_lines(paths, year=None):
    """Yield (path, line number, line) for each file, gzipped or not.

    Rotated logs are usually compressed, and refusing to read auth.log.1.gz
    would make this useless on a real machine, so the file is opened by its
    magic bytes rather than by its extension.
    """
    import gzip
    import io

    for path in paths:
        with open(path, "rb") as handle:
            head = handle.read(2)
            handle.seek(0)
            if head == b"\x1f\x8b":
                text = gzip.open(handle, "rt", encoding="utf-8", errors="replace")
            else:
                text = io.TextIOWrapper(handle, encoding="utf-8", errors="replace")
            with text as stream:
                for number, line in enumerate(stream, start=1):
                    yield path, number, line
