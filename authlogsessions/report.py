"""Printing the reconstructed sessions.

The order is deliberate and it is the opposite of most log tools. The summary
table comes first because that is what someone wants in the first ten seconds,
then a short narrative per address, then the handful of lines that are actually
alarming. A report that opens with 4,000 raw lines is a report nobody reads.
"""

from . import parse
from . import sessions


def human_duration(seconds):
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def stamp(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "unknown"


class Report:
    """Everything the output needs, gathered once."""

    def __init__(self, events, files, line_count, host=None):
        self.events = events
        self.files = files
        self.line_count = line_count
        self.host = host
        self.sources, self.orphans = sessions.reconstruct(events)
        self.unrecognised = [event for event in events if event.action == parse.UNKNOWN]

        moments = [event.timestamp for event in events if event.timestamp]
        self.first = min(moments) if moments else None
        self.last = max(moments) if moments else None

    @property
    def window(self):
        if not self.first or not self.last:
            return 0
        return (self.last - self.first).total_seconds()

    def only(self, address):
        """A copy of this report narrowed to one address."""
        kept = [event for event in self.events if event.address == address]
        narrowed = Report(kept, self.files, self.line_count, self.host)
        narrowed.unrecognised = self.unrecognised
        return narrowed


def _source_line(source):
    return (f"{source.attempts:>6,} event(s)  {source.address:<39} "
            f"{len(source.connections):>3} connection(s)  {sessions.outcome(source)}")


def _narrative(source, width=100):
    out = []
    out.append(f"{source.address}")
    out.append(f"  active from {stamp(source.first)} to {stamp(source.last)} "
               f"({human_duration((source.last - source.first).total_seconds() if source.first and source.last else None)})")
    out.append(f"  {len(source.connections)} connection(s), {source.attempts} line(s), "
               f"{source.failures} failure(s), {source.successes} success(es)")

    if source.usernames:
        top = ", ".join(f"{name} x{count}" for name, count in source.usernames.most_common(5))
        extra = len(source.usernames) - 5
        out.append(f"  usernames: {top}" + (f", and {extra} more" if extra > 0 else ""))

    for connection in source.connections:
        for event in connection.events:
            if event.action in sessions.SUCCESS_ACTIONS:
                out.append(f"  got in as {event.user or 'unknown'} at {stamp(event.timestamp)}"
                           + (f" on port {connection.port}" if connection.port else ""))

    for event in source.commands[:5]:
        out.append(f"  ran: {event.detail}")
    if len(source.commands) > 5:
        out.append(f"  and {len(source.commands) - 5} more command(s)")

    for event in source.accounts[:5]:
        out.append(f"  account {event.detail}: {event.user or 'unknown'}")

    return "\n".join(line[:width] for line in out)


def render(report, top=10, focus=None, width=100):
    out = []

    out.append(f"{len(report.files)} file(s), {report.line_count:,} line(s), "
               f"{len(report.events):,} recognised, {len(report.sources)} source address(es)")
    if report.host:
        out.append(f"host {report.host}")
    if report.first:
        out.append(f"window {stamp(report.first)} to {stamp(report.last)} "
                   f"({human_duration(report.window)})")
    out.append("")

    shown = report.sources if not focus else [s for s in report.sources if s.address == focus]
    if not shown:
        out.append(f"nothing from {focus}" if focus else "nothing was recognised in these logs")
        out.append("")
        return "\n".join(out)

    out.append("sources, busiest first")
    for source in shown[:top]:
        out.append("  " + _source_line(source))
    if len(shown) > top:
        rest = shown[top:]
        out.append(f"  and {len(rest)} more, {sum(item.attempts for item in rest):,} event(s) "
                   f"between them")
    out.append("")

    for source in shown[:top if not focus else len(shown)]:
        out.append(_narrative(source, width=width))
        out.append("")

    lines = sessions.findings(report.sources if not focus else shown)
    out.append("what stands out")
    if lines:
        for line in lines:
            out.append(f"  - {line}")
    else:
        out.append("  nothing here stands out")
    out.append("")

    if report.orphans:
        out.append(f"{len(report.orphans)} line(s) could not be tied to a connection, so "
                   "they are not counted against anyone:")
        out.append(f"  {report.orphans[0].detail[:width - 4]}")
        out.append("")

    if report.unrecognised:
        out.append(f"{len(report.unrecognised)} line(s) were not recognised, first was:")
        out.append(f"  {report.unrecognised[0].detail[:width - 4]}")
        out.append("")

    return "\n".join(out)


def as_dict(report, top=10):
    """The same reconstruction as data, for anything that wants to plot it."""
    return {
        "files": list(dict.fromkeys(report.files)),
        "lines": report.line_count,
        "events": len(report.events),
        "unrecognised": len(report.unrecognised),
        "first": report.first.isoformat() if report.first else None,
        "last": report.last.isoformat() if report.last else None,
        "sources": [
            {
                "address": source.address,
                "first": source.first.isoformat() if source.first else None,
                "last": source.last.isoformat() if source.last else None,
                "connections": len(source.connections),
                "events": source.attempts,
                "failures": source.failures,
                "successes": source.successes,
                "usernames": dict(source.usernames.most_common(10)),
                "succeeded_as": sessions.succeeded_as(source),
                "outcome": sessions.outcome(source),
                "commands": [event.detail for event in source.commands],
                "account_changes": [
                    {"user": event.user, "what": event.detail,
                     "when": event.timestamp.isoformat() if event.timestamp else None}
                    for event in source.accounts],
            }
            for source in report.sources[:top]
        ],
        "findings": sessions.findings(report.sources),
    }
