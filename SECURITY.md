# Security

BrollyZapper brokers credentials for a Lightning node. If you have found a way to make it
spend what it should not, read what it should not, or mint authority it should not hold,
please report it privately.

**Report via GitHub's private vulnerability reporting** — *Security → Report a
vulnerability* on this repository. That opens a private thread with the maintainer; nothing
is public until a fix ships.

Please do **not** open a public issue for a vulnerability. A public issue is a disclosure.

## What counts

Anything that crosses the boundaries the design promises:

- the server container obtaining spend authority without the operator's ceremony;
- the guard minting a credential broader than the URI list it documents;
- a path from the public LNURL endpoints to anything but the three public routes;
- a stored or logged secret (keys, macaroons, pairing secrets, preimages).

Rate-limit tuning, UI issues and dependency reports with no reachable path are welcome as
ordinary issues.

## Supported versions

The latest release. Fixes ship as a new release; nothing is backported.
