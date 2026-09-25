# network-exposure-tools

Two small Python scripts for answering the same question from two directions:
**what on my home network is reachable that I did not intend?**

Both are for networks you own. Nothing here is stealthy, and `netpentest.py`
refuses public IP ranges unless you explicitly override it.

## `check_exposure.py` — what has UPnP quietly opened?

Consumer routers let apps and devices punch holes in the firewall via UPnP
without telling you. This script asks the router for its list.

How it works: sends an SSDP discovery multicast on the LAN to find the
router's Internet Gateway Device service, then walks its port-mapping table
over SOAP. It talks only to your own router, needs no login, and sends
nothing off-network.

```
$ python check_exposure.py
Discovering UPnP Internet Gateway Devices on your LAN...

Found 3 UPnP port mapping(s):

EXT PORT  PROTO  INTERNAL              ENABLED  DESCRIPTION
--------------------------------------------------------------------------------
32400     TCP    192.168.1.100:32400   1        Media Server
3389      TCP    192.168.1.101:3389    1        Remote Desktop
...

*** HIGH-RISK EXPOSURE ***
  - RDP on 192.168.1.101:3389 is reachable from the internet via external port 3389/TCP
```

Flags SSH, RDP, SMB, FTP, Telnet, VNC, and NetBIOS. Limitation: UPnP only
knows about the *dynamic* mappings. Static port-forwarding rules you set in
the router's admin page are invisible to it — check those by hand.

No dependencies beyond the standard library.

## `netpentest.py` — one-pass nmap sweep with a readable report

Wraps nmap into a single run — host discovery, service/version detection,
OS guess, and the NSE `vuln` script set against anything open — then writes
a Markdown and an HTML report.

```
python netpentest.py 192.168.1.0/24
python netpentest.py 192.168.1.10 --full-ports     # all 65535 ports, slow
python netpentest.py 192.168.1.0/24 --skip-vuln    # discovery + services only
```

Safety rails:

- Refuses anything that is not an RFC 1918 / loopback range unless you pass
  `--allow-public`.
- Prints an authorization banner and requires you to type `I CONFIRM`
  (`--yes` skips it for scripted runs).
- Reports go in `reports/`, which is git-ignored, because a scan of your own
  network is exactly the thing you do not want to commit.

Requires nmap on the PATH (`winget install Insecure.Nmap` on Windows, or
your package manager elsewhere). Run it elevated for OS detection.

## Why

I run a handful of self-hosted services at home and wanted a habit, not a
one-off: a fast check that nothing new has been exposed since last time.
`check_exposure.py` takes five seconds and catches the "some app enabled
UPnP" case; `netpentest.py` is the slower, thorough version for a quiet
Sunday.

License: MIT.
