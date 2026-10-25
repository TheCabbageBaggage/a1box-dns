# Protocol notes — A1/Zyxel web API

Notes gathered by watching the box's own web UI bundle. Applies to the V5.15
GUI used on the A1 WLAN Box (Zyxel DX3301-T0) and, with high probability, to the
AX/DX/EX/PX series in general.

Everything below is unauthenticated observation of the device you own — no
firmware was modified.

## 1. Where the settings live

The SPA is served from `/` and loads chunks from `/static/js/app.<name>.js`
(`networksetting`, `security`, `maintenance`, …). The LAN page exists as
`/pages/network/homeNetworking/lanSetup.js` and saves via

```
PUT /cgi-bin/DAL?oid=lan
```

`oid=lan` returns exactly one object (`Object[0]`) containing the whole LAN
configuration:

```json
{
  "Name": "Default",
  "IPAddress": "192.168.1.1",
  "SubnetMask": "255.255.255.0",
  "DHCPType": "DHCPServer",
  "EnableDHCP": true,
  "DHCP_MinAddress": "192.168.1.2",
  "DHCP_MaxAddress": "192.168.1.254",
  "DHCP_LeaseTime": 86400,
  "DNS_Type": "DNSProxy",
  "DNS_Servers1": "",
  "DNS_Servers2": "",
  "IPv6_LanEnable": true,
  "IPv6_IdentifierType": "EUI-64",
  "IPv6_DNSAssign": "RA_DHCP",
  "Ipv6_DNSServer1": "Proxy",
  "Ipv6_DNSServer2": "Proxy",
  "Ipv6_DNSServer3": "Proxy"
}
```

* `DNS_Type` — `DNSProxy` (box hands out its own IP), `Static` (hand out
  `DNS_Servers1`/`DNS_Servers2`), `FromISP`.
* `DNS_Servers2` is real: the UI deletes the key when the field is left empty,
  but the backend stores and advertises a second address.
* `Ipv6_DNSServer1..3` — `Proxy` makes the box advertise itself as IPv6 DNS via
  router advertisements, which lets IPv6 clients bypass a custom resolver. Use
  `None` to suppress that.

## 2. Login

Plaintext against the login endpoint is rejected with `{"result":"Decrypt Fail"}`
— which is also the fastest way to find the right endpoint: `/cgi-bin/UserLogin`
answers `401 Invalid Username or Password` no matter what, while `/UserLogin`
answers `Decrypt Fail`.

```
GET /getRSAPublickKey          →  {"RSAPublicKey": "-----BEGIN PUBLIC KEY-----..."}
POST /UserLogin
```

The body is a three-field envelope:

| field | content |
| --- | --- |
| `content` | base64(AES-256-CBC(PKCS#7(json), key = K, iv = IV[:16])) |
| `key` | base64(RSA_PKCS1v15(base64(K))) |
| `iv` | base64(IV) |

* `K` and `IV` are 32 random bytes each, base64 encoded before use.
* The encrypted material for the `key` field is the **base64 string** of `K`,
  not the raw bytes.
* RSA padding is PKCS#1 v1.5 (what JSEncrypt does — not OAEP).

Plaintext credentials:

```json
{
  "Input_Account": "admin",
  "Input_Passwd": "<base64(password)>",
  "currLang": "de",
  "RememberPassword": 0,
  "SHA512_password": false
}
```

Success sets a `Session` cookie and returns an encrypted body containing
`sessionkey`, `loginLevel` and `result: "ZCFG_SUCCESS"`.

## 3. Subsequent calls

Responses from `/cgi-bin/*` are encrypted with the same AES key:

```
AES-256-CBC(content, key = K, iv = response.iv)   →  JSON
```

Requests need `K` again, but no RSA part:

```json
{ "content": "<base64 ciphertext>", "iv": "<base64 of a fresh 32-byte iv>" }
```

**The `sessionkey` is rotated by every response.** Re-read it each time and send
it as the header:

```
CSRFToken: <sessionkey>
```

Without that header writes fail with `403` and an empty body. GETs work with the
`Session` cookie alone.

## 4. Writing

`PUT /cgi-bin/DAL?oid=lan` with the flat LAN object (the same one you got from
the GET), including `"logout": 0`.

Two details that cost time:

* `IPv6_IdentifierType` must be `EUI64`, not the `EUI-64` the box returns in the
  GET — otherwise the box answers `ZCFG_INVALID_PARAM_VALUE` naming that field.
* On a rejected write the body still carries `ReplyMsg` with the offending field
  name; that is the fastest way to find further normalisations.

A successful write answers:

```json
{"result": "ZCFG_SUCCESS", "ReplyMsg": "MLDSnoopingMode", "sessionkey": "..."}
```

`ReplyMsg` here is not an error — it is the last field the backend touched.

## 5. Verifying the result

`GET /cgi-bin/DAL?oid=lan` reflects the stored values immediately. What clients
receive is visible over DHCP:

```
nmap --script broadcast-dhcp-discover -e eth0
  ...
  |     Domain Name Server: 192.168.1.10, 192.168.1.1
```

## 6. Notes on related A1 devices

A1 removed the DNS fields on other boxes the same way. For the **A1 Hybrid Box**
(Huawei EchoLife DN9245X6/DN9245W) the community approach is a browser snippet
posting to `set.cgi` (`X_HW_DNSList`). This project takes the Zyxel DAL route
because the DX3301-T0 speaks JSON, not the Huawei `set.cgi` dialect.
