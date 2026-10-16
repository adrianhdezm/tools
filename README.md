# tools

Standalone scripts. Run any of them with `uv run scripts/<name>.py`.

## netscan

Finds live hosts on your local network, with their MAC addresses, hostnames and, optionally, open ports.

```sh
uv run scripts/netscan.py                  # scan the /24 this machine is on
uv run scripts/netscan.py 10.0.0.0/24      # scan a specific network
uv run scripts/netscan.py --ports          # also check common TCP ports
uv run scripts/netscan.py -p 22,8000-8100  # check specific ports
```
