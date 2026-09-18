"""Rebuild what an attacker did from Linux authentication logs.

Feed it an auth.log, a secure file, a journal export or a rotated copy of any of
those, and it reconstructs the connections behind the login attempts, groups
them by source address, and says what each address tried and whether it worked.

Nothing here talks to a machine. The logs come from wherever you copied them.
"""

__version__ = "0.1.0"
