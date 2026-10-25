# a1box_dns — set a custom LAN DNS server on an A1 WLAN Box (Zyxel DX3301-T0)

A1 (Austria) ships their WLAN Box — a rebranded **Zyxel DX3301-T0** — with the
*LAN Setup* page removed from the web UI. Under **Heimnetzwerk** you only get
Static DHCP, UPnP and Wake on LAN. The consequence: you cannot tell the built-in
DHCP server to hand out your own DNS server, so a Pi-hole / AdGuard Home /
Blocky stays invisible to the whole network unless you configure every client
by hand.

The setting is gone from the *menu*, not from the *firmware*. The box still
implements it and its own web UI still contains the page
(`/pages/network/homeNetworking/lanSetup.js`, backend object `oid=lan`). This
tool talks to the box's own encrypted JSON API and writes the value the UI would
have written.

No firmware modification, no WAN changes, no port forwarding — and every change
is reversible with a single command.

## What it does

* `show` — print the current LAN DNS settings
* `backup` — save the whole LAN object to a timestamped JSON file
* `set` — point the DHCP-advertised DNS at your own resolver (primary **and**
  optional secondary)
* `set --ipv6-dns none` — stop the box advertising itself as IPv6 DNS via router
  advertisements (otherwise IPv6-capable clients silently bypass your resolver)
* `restore <file>` — write a previously saved LAN object back
* `default` — restore A1's factory behaviour (the box is its own DNS)

## Requirements

* Access to the box web UI at `http://192.168.1.1` with the **admin** login
  (printed on the WLAN card that came with the box)
* Python 3.8+ and `cryptography`

```bash
pip install -r requirements.txt
```

## Usage

```bash
export A1BOX_HOST=http://192.168.1.1     # optional, that is the default
export A1BOX_USER=admin                  # optional
export A1BOX_PW='your-admin-password'    # required — never stored anywhere

./a1box_dns.py show
./a1box_dns.py backup
./a1box_dns.py set --dns1 192.168.1.10 --dns2 192.168.1.1 --ipv6-dns none --dry-run
./a1box_dns.py set --dns1 192.168.1.10 --dns2 192.168.1.1 --ipv6-dns none
```

A backup is written before every write. Example output:

```
planned change:
  DNS_Type         'DNSProxy' -> 'Static'
  DNS_Servers1     None -> '192.168.1.10'
  DNS_Servers2     None -> '192.168.1.1'
  Ipv6_DNSServer1  'Proxy' -> 'None'
  Ipv6_DNSServer2  'Proxy' -> 'None'
  Ipv6_DNSServer3  'Proxy' -> 'None'
backup: ./a1box-lan-20260101-120000.json
LAN DNS settings
  DNS_Type         'Static'
  DNS_Servers1     '192.168.1.10'
  DNS_Servers2     '192.168.1.1'
```

### Undo

```bash
./a1box_dns.py restore a1box-lan-20260101-120000.json   # exact state from before
./a1box_dns.py default                                  # A1 factory behaviour
```

### Why a secondary DNS is worth setting

The box accepts **two** IPv4 DNS servers even though the manual shows a single
field. Pointing the primary at your Pi-hole and the secondary at the router
gives you filtering *and* a failover: if the Pi-hole is down, clients fall back
to the router and the internet keeps working (unfiltered). Set only `--dns1`
for strict filtering with no fallback.

## Verifying it

Look at what the box actually offers over DHCP — from another Linux host on the
same L2 segment:

```bash
sudo nmap --script broadcast-dhcp-discover -e eth0
```

```
Domain Name Server: 192.168.1.10, 192.168.1.1
```

On a client, check that the new resolver is in use:

```bash
resolvectl status | grep -E 'Current DNS|DNS Servers'
```

## Rolling it out

Existing clients keep their old lease (typically 24 h) and therefore their old
DNS server. To apply it everywhere at once, either reboot the box
(*Wartung → Neustart*) or reconnect each client:

```bash
nmcli connection down <name> && nmcli connection up <name>
```

## Tested on

| Device | Firmware | Result |
| --- | --- | --- |
| A1 WLAN Box / Zyxel DX3301-T0 | V5.50(ACIM.0)b21_MU (A1 build) | working, survives a reboot |

Reports for other A1-boxed Zyxel models (DX3300-T0, EX3301-T0, DX5401-B0 …) are
welcome — the DAL/`oid=lan` mechanism is shared across the AX/DX/EX/PX series.

## Caveats

* **Provider provisioning.** The box is managed by A1 (TR-069). A firmware
  update or a re-provisioning could reset this value. Check with
  `./a1box_dns.py show` after a reboot; if it reverted, re-run `set`.
* **Wrong DNS = broken internet.** If you point the box at a resolver that does
  not answer, every client loses name resolution. Always keep a reachable
  secondary (the router) or be ready to run `default`.
* **Two DHCP servers.** Do not combine this with a DNS/DHCP container that also
  runs DHCP on the same network.
* **Device ownership.** Depending on your contract the box may be A1 property.
  This tool writes a setting the firmware already supports and is fully
  reversible, but check your contract before using it.
* No warranty, use at your own risk.

## How it works

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the reverse-engineered login and
request format (AES-256 payloads, RSA-wrapped key, `CSRFToken` header, rotating
session key).

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with A1 Telekom Austria or Zyxel. Product names are trademarks of
their respective owners.
