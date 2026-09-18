"""Grouping events into connections, and connections into sources.

A source port identifies one TCP connection on a machine that is being attacked,
which is what makes this more than counting lines. Five failed passwords on port
51234 followed by an accepted one is a single session that got in. The same ten
failures spread over ten ports is a scanner that never completed a login.

So the events are grouped twice: first by address and port, which reconstructs
the individual connections, then by address, which is the story worth printing.
"""

from collections import Counter

from . import parse

FAILURE_ACTIONS = (parse.FAILED_PASSWORD, parse.INVALID_USER, parse.PAM_FAILURE,
                   parse.MAX_ATTEMPTS)
SUCCESS_ACTIONS = (parse.ACCEPTED_PASSWORD, parse.ACCEPTED_KEY)


class Connection:
    """One connection to this machine, as far as the log describes it.

    These are built up as the events are read, so they are plain objects rather
    than named tuples. A named tuple here was the first thing I wrote and it
    fails at the first assignment, which is a lesson worth leaving in the comment.
    """

    def __init__(self, address, port, timestamp, event):
        self.address = address
        self.port = port
        self.first = timestamp
        self.last = timestamp
        self.events = [event]


class Source:
    """Everything one address did, across every connection it opened."""

    def __init__(self, address, timestamp):
        self.address = address
        self.first = timestamp
        self.last = timestamp
        self.connections = []
        self.attempts = 0
        self.failures = 0
        self.successes = 0
        self.usernames = Counter()
        self.commands = []
        self.accounts = []

# An address trying this many different names is working from a list rather than
# mistyping a login. Ten is low enough to catch a short spray and high enough
# that a person fumbling their own username does not trip it.
DICTIONARY_USERS = 10

# Attempts per minute that count as fast for a single address.
FAST_ATTEMPTS_PER_MINUTE = 10


def _sort_key(connection):
    return (connection.first or _NEVER, connection.address, connection.port or 0)


def _earliest(current, candidate):
    """The earlier of two times, either of which may be missing."""
    if current is None:
        return candidate
    if candidate is None:
        return current
    return min(current, candidate)


def _latest(current, candidate):
    if current is None:
        return candidate
    if candidate is None:
        return current
    return max(current, candidate)


_NEVER = 0


def build_connections(events):
    """One Connection per address and source port, earliest first.

    A line can name an address without naming a port, which pam failures often
    do. Those are attached to the most recent connection from that address, since
    that is almost certainly the connection they happened on, rather than being
    left as a connection of their own with no port.
    """
    grouped = {}
    latest = {}

    for event in events:
        if not event.address:
            continue

        key = (event.address, event.port)
        if event.port is None and event.address in latest:
            key = latest[event.address]

        connection = grouped.get(key)
        if connection is None:
            grouped[key] = Connection(event.address, event.port,
                                      event.timestamp, event)
            latest[event.address] = key
            continue

        connection.events.append(event)
        if event.timestamp:
            connection.first = _earliest(connection.first, event.timestamp)
            connection.last = _latest(connection.last, event.timestamp)
        latest[event.address] = key

    return sorted(grouped.values(), key=_sort_key)


def build_sources(connections):
    """Roll the connections up into one entry per address, busiest first."""
    grouped = {}

    for connection in connections:
        source = grouped.get(connection.address)
        if source is None:
            source = Source(connection.address, connection.first)
            grouped[connection.address] = source

        source.connections.append(connection)
        source.first = _earliest(source.first, connection.first)
        source.last = _latest(source.last, connection.last)

        for event in connection.events:
            source.attempts += 1
            if event.action in FAILURE_ACTIONS:
                source.failures += 1
                if event.user:
                    source.usernames[event.user] += 1
            elif event.action in SUCCESS_ACTIONS:
                source.successes += 1
                if event.user:
                    source.usernames[event.user] += 1
            elif event.action == parse.SUDO_COMMAND:
                source.commands.append(event)
            elif event.action == parse.ACCOUNT_CHANGE:
                source.accounts.append(event)

    return sorted(grouped.values(), key=lambda item: (-item.attempts, item.address))


def attribute_loose(events, sources):
    """Place the events that carry no address onto the account they belong to.

    sudo and the account tools log a user, a command and a time, and no address
    at all, so there is nothing on the line to group by. The only honest way to
    place them is the account they name: if an address authenticated as that user
    and nothing later took the account over, the command is theirs. Anything that
    cannot be placed that way is returned rather than guessed at.
    """
    logins = []
    for source in sources:
        for connection in source.connections:
            for event in connection.events:
                if event.action in SUCCESS_ACTIONS and event.user and event.timestamp:
                    logins.append((event.timestamp, event.user, source))
    logins.sort(key=lambda item: item[0])

    placed = 0
    orphans = []

    for event in events:
        if not event.timestamp:
            orphans.append(event)
            continue

        if event.action == parse.ACCOUNT_CHANGE:
            # useradd records the account being created, never who created it, so
            # the only thing to go on is the session that was open at the time.
            # That is an inference, and it is reported as one.
            owner = None
            for moment, user, source in logins:
                if moment <= event.timestamp:
                    owner = source
            if owner is None:
                orphans.append(event)
                continue
            owner.accounts.append(event)
            placed += 1
            continue

        if not event.user:
            orphans.append(event)
            continue

        owner = None
        for moment, user, source in logins:
            if user == event.user and moment <= event.timestamp:
                owner = source

        if owner is None:
            orphans.append(event)
            continue

        if event.action == parse.SUDO_COMMAND:
            owner.commands.append(event)
        else:
            owner.attempts += 1
        placed += 1

    return placed, orphans


def reconstruct(events):
    """Connections, then sources, then the events with no address on them.

    Returns (sources, orphaned events). An event lands in the second list when
    nothing in the log can tie it to a connection, which is worth surfacing
    rather than quietly dropping.
    """
    connections = build_connections(events)
    sources = build_sources(connections)
    loose = [event for event in events if not event.address]

    placed, orphans = attribute_loose(loose, sources)
    return sources, orphans


def succeeded_as(source):
    """The accounts this address got in as, in the order it managed it."""
    names = []
    for connection in source.connections:
        for event in connection.events:
            if event.action in SUCCESS_ACTIONS and event.user not in names:
                names.append(event.user)
    return names


def minutes(source):
    """How long this address was active, in minutes, at least one."""
    if not source.first or not source.last:
        return 1.0
    return max(1.0, (source.last - source.first).total_seconds() / 60.0)


def rate(source):
    """Attempts per minute for the whole window this address appears in."""
    return source.attempts / minutes(source)


def outcome(source):
    """A short phrase for what this address achieved."""
    got_in = succeeded_as(source)
    if got_in and source.failures:
        return f"got in as {', '.join(got_in)} after {source.failures} failure(s)"
    if got_in:
        return f"got in as {', '.join(got_in)} without a single failure first"
    if source.attempts:
        return "no successful login"
    return "nothing read"


def findings(sources, limit=12):
    """The lines worth printing under what stands out.

    Ordered with the worst first, because a report where the readable part is
    buried under someone else's scan is a report nobody finishes.
    """
    lines = []

    for source in sources:
        got_in = succeeded_as(source)

        if got_in and source.accounts:
            names = sorted({event.user for event in source.accounts if event.user})
            lines.append(
                f"{source.address} changed accounts after logging in"
                + (f" ({', '.join(names)})" if names else "")
                + ", which is worth reading line by line")

    for source in sources:
        got_in = succeeded_as(source)
        if not got_in or source.failures:
            continue
        # A key login is meant to work first time. Flagging it would put a line
        # in front of every deploy user on the machine and teach the reader to
        # skim, so only a password that worked first time is worth naming.
        if any(event.action == parse.ACCEPTED_KEY
               for connection in source.connections
               for event in connection.events):
            continue
        lines.append(f"{source.address} logged in as {', '.join(got_in)} "
                     "with no failed attempt before it, so the credentials "
                     "were probably already valid")

    for source in sources:
        got_in = succeeded_as(source)
        if got_in and source.failures:
            lines.append(f"{source.address} failed {source.failures} time(s) and "
                         f"then got in as {', '.join(got_in)}")

    for source in sources:
        if len(source.usernames) >= DICTIONARY_USERS and not succeeded_as(source):
            lines.append(f"{source.address} tried {len(source.usernames)} different "
                         "usernames, which is a list rather than a mistyped login")

    for source in sources:
        if rate(source) >= FAST_ATTEMPTS_PER_MINUTE and not succeeded_as(source):
            plural = "minute" if round(minutes(source)) == 1 else "minutes"
            lines.append(f"{source.address} managed {rate(source):.0f} attempts a "
                         f"minute for {minutes(source):.0f} {plural}")

    for source in sources:
        if source.commands:
            lines.append(f"{source.address} has {len(source.commands)} command(s) "
                         "recorded after authenticating")

    return lines[:limit]
