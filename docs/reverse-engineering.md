# Sonos S2 — How the Controller Drives YouTube Music (Reverse-Engineering)

> Date: 2026-11-25. Goal: understand how the Sonos desktop app (S2) browses and
> plays YouTube Music, in order to reproduce the same control from Home Assistant.
> All captures were done against my **own** speaker and **own** account for
> personal interoperability.

---

## 1. Environment

- Machine: ThinkPad T480 (Hackintosh), macOS (Darwin 24.6).
- App: `/Applications/Sonos.app` — legacy S2 desktop (`com.sonos.macController2`,
  build `90.0-82050`). Data: `~/Library/Application Support/SonosV2/`.
- Speaker: **Sonos Move**, `<speaker-ip>`, `RINCON_<MAC>01400`, S2 18.3.
  - Household: `Sonos_<HOUSEHOLD>`
  - `zpSSLPort: 1443` (from `connectionsettings.txt`)
- YouTube Music = a Sonos SMAPI service, **sid=284**, account serial **sn=3**.

---

## 2. Methodology

### 2.1. Bypassing Hardened Runtime
The original binary is signed with Hardened Runtime (`flags=runtime`, TeamID `2G4LW83Q3E`),
so Frida cannot attach to it. Fix: copy the app into the scratchpad and re-sign it
**ad-hoc without** hardened runtime, adding `get-task-allow`:

```bash
cp -R /Applications/Sonos.app ./SonosPatched.app
# entitlements: com.apple.security.get-task-allow = true
codesign --force --deep -s - --entitlements ent.plist SonosPatched.app
# flags become 0x2(adhoc), runtime removed → Frida attaches
```
The original `/Applications/Sonos.app` was **left untouched**.

### 2.2. Frida instrumentation
- `driver.py` — spawns the patched binary under Frida, loads `tap.js`,
  writes a length-prefixed binary frame log.
- Hooked TLS `SSL_write`/`SSL_read` and plain sockets (`write/read/send/recv`
  + the `$NOCANCEL`/`__*_nocancel` variants — on macOS CFNetwork writes via nocancel).
- A `connect()` hook (Frida 17 removed `Module.findExportByName`, so symbols were
  resolved by enumerating module exports) — revealed ALL destination addresses/ports
  in real time.

### 2.3. The key snag — four TLS stacks
The app bundles several TLS implementations at once:
| Stack | What it serves |
|---|---|
| system **boringssl** (CFNetwork) | album art `yt3.googleusercontent.com`, Sentry telemetry |
| system **SecureTransport** (`Security`) | auxiliary |
| bundled **OpenSSL** (`libssl.48`/`libcrypto.46` via `libcurl.4`) | auxiliary |
| **statically-linked mbedTLS** (inside the main binary) | **all the important traffic: YT Music SMAPI + the speaker's local API** |

mbedTLS was located via RTTI symbols (`mbedtls_x509_crt`) in the binary. The functions
are stripped to local → not resolvable by name.

### 2.4. Finding `mbedtls_ssl_write` without symbols
1. Hook `write()`; when ciphertext went out to the socket on `:1443`/Google, take a
   `Thread.backtrace(Backtracer.ACCURATE)`.
2. Tell handshake (`0x16`) from application data (`0x17`) by the first TLS-record byte.
3. In the app-data stack the return address `MAIN+0xc0a833` landed inside `mbedtls_ssl_write`.
4. Scan the prologue backwards (`55 48 89 e5` = `push rbp; mov rbp,rsp`) → entry point
   **`MAIN+0xc0a740`** (`base` was `0x10ed48000` on that run).
5. `mbedtls_ssl_read` found the same way (`≈ MAIN+0xc0c2e0`).
6. Hook the entry of `mbedtls_ssl_write(ctx, buf, len)` → `buf` = **plaintext**.

Scripts: `mbed_discover.py` (backtraces), `mbed_capture.py` (full plaintext dump to
`muse_plain.bin`), `tap.js`/`driver.py`/`h2parse.py` (earlier stages).

---

## 3. Architecture: four network channels

| Channel | Encryption | Purpose |
|---|---|---|
| `<speaker-ip>:1400` | none (HTTP/UPnP) | SSDP discovery, `GetPositionInfo` polling, local `Browse` (`Q:0`, `FV:2`), `AVTransport` (playback/transport) |
| `<speaker-ip>:1443` | mbedTLS | speaker's local REST API `/api/v1/...` (status/battery/settings) |
| `music.googleapis.com:443` | mbedTLS | **YouTube Music browse & search (SMAPI)** |
| Google `:443` | boringssl | album art + Sentry |

**QUIC/HTTP3 is not used** (verified by the `connect()` hook — not a single UDP:443).

---

## 4. YouTube Music browse protocol (decrypted)

The app talks to Google **directly**:

```
POST https://music.googleapis.com/v1:sendRequest  HTTP/1.1
HOST: music.googleapis.com
X-Goog-Api-Key: AIza…<REDACTED>           # Sonos app's Google API key
AUTHORIZATION: Bearer ya29.<REDACTED>     # YT Music account OAuth access token (~1h)
X-Sonos-Api-Key: 85f746ce-7307-4acf-bc36-71c9979d7b00
X-Sonos-Controller-ID: XX:XX:XX:XX:XX:XX
ACCEPT-ENCODING: gzip
CONTENT-TYPE: text/xml; charset="utf-8"
SOAPACTION: "http://www.sonos.com/Services/1.1#getMetadata"
```

Body — Sonos SMAPI (SOAP 1.1):

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Header>
  <context xmlns="http://www.sonos.com/Services/1.1"><timeZone>+2:00</timeZone></context>
  <credentials xmlns="http://www.sonos.com/Services/1.1">
   <loginToken><householdId>Sonos_<HOUSEHOLD>_<hhsfx></householdId></loginToken>
   <deviceId>XX-XX-XX-XX-XX-XX:B</deviceId>
   <deviceProvider>Sonos</deviceProvider>
  </credentials>
 </s:Header>
 <s:Body>
  <getMetadata xmlns="http://www.sonos.com/Services/1.1">
   <id>root</id><index>0</index><count>100</count>
  </getMetadata>
 </s:Body>
</s:Envelope>
```

### Captured SMAPI operations
- `getMetadata` — browse nodes. `<id>` = `root`, `ARTISTS`, or a node id like
  `ALkSOi...` (base64-ish YouTube Music catalog identifiers).
- `getExtendedMetadata` — detailed item card.
- `search` — search:
  ```xml
  <search xmlns="http://www.sonos.com/Services/1.1">
    <id>ARTISTS</id><term>mogwai</term><index>0</index><count>100</count>
  </search>
  ```
- `getLastUpdate` — catalog/favorites version check.

> Response bodies (`mbedtls_ssl_read`) weren't dumped in the first session (the read-hook
> heuristic latched onto the wrong function); the requests were captured in full. The
> response format is SMAPI `getMetadataResult` with `mediaCollection`/`mediaMetadata`;
> art points to `yt3.googleusercontent.com`. (Responses were later confirmed working via
> the PoC in §11, which parses exactly these structures.)

### 4.1. Artist navigation & malformed faults (client-layer findings)

Two non-obvious things surfaced while building our own client (`soco_ytmusic.py`):

**(A) The server sometimes returns invalid XML inside a fault.** On a bad request it
replies with a SOAP `<fault>`, but the `<faultstring>` embeds a raw Java/RPC dump with
**unescaped** `<...>`, e.g. `ImmutableList<...entitybrowser.v1.Entity>` and
`cloud_project_number:<…>`. A strict parser (soco's `XML.fromstring`) chokes on this
(`mismatched tag`) and soco mislabels the crash as "empty response → not authenticated".
The official app never hits this: it (1) doesn't provoke the error (it browses with valid
ids) and (2) reads the **structured status code** `Code: INVALID_ARGUMENT` / `AppErrorCode=3`,
not the text blob. Our fix: parse the faultstring with **regex + `html.unescape`**, not XML;
separate a real auth fault (`TokenRefreshRequired`/`AuthTokenExpired`/`res:1035…`) from an
application error (`Malformed resource name`, `INVALID_ARGUMENT`), and do **not** run a
pointless token refresh on the latter.

**(B) The search artist id is NOT browsable.** `search("ARTISTS")` returns a ~69-char id;
`getMetadata`/`getExtendedMetadata` on it both fail with `INVALID_ARGUMENT, Malformed
resource name`. The canonical **browsable** `artistId` (~48 chars) instead lives **inside a
track**:
```
getExtendedMetadata(trackId) → <trackMetadata><artistId>ALkSOi…(48)</artistId>
                                              <albumId>ALkSOi…(48)</albumId>
```
`getMetadata(canonical artistId)` returns the **artist page**: playlists `Artist Shuffle` /
`Artist Radio` / `Top Songs` + albums. But the track ids inside `Top Songs` are **long
(~106, playlist-context)** and not directly playable; resolve each back to the short
playable id via `getExtendedMetadata(longId) → <mediaMetadata><id>` = short ~48 (the form in
§6). A short album-track id plays directly; a long playlist/search id does not.

---

## 5. Speaker local REST API (:1443)

Also over mbedTLS, but this is **not** the catalog:
```
GET /api/v1/players/RINCON_<MAC>01400/hardwareStatus/battery
GET /api/v1/users/<userId>/settings
```

---

## 6. Playback (local UPnP :1400, cleartext)

A YT Music track is enqueued/played through `AVTransport` on the speaker. Everything
needed (the account is already linked on the speaker, `sn=3`):

```
URI:       x-sonosapi-hls-static:<trackId>?sid=284&flags=8&sn=3
DIDL item: id="00032020<trackId>" parentID="00020000" restricted="true"
class:     object.item.audioItem.musicTrack
DESC:      <desc id="cdudn" nameSpace="urn:schemas-rinconnetworks-com:metadata-1-0/">
             SA_RINCON72711_X_#Svc72711-<hhsfx>-Token</desc>
res protocolInfo: sonos.com-http:*:application/x-mpegURL:*
```
Enqueued via `AVTransport#AddURIToQueue` (same as soco / Music Assistant).

> ⚠️ Critical: `<trackId>` must be the **short ~48-char** `<id>` from an **album's**
> `getMetadata`. The long ~100-char ids from playlists/search do **not** work directly in the URI.

**✅ PLAYBACK VERIFIED LIVE (2026-11-25)** — `play_album.py` (soco 0.32.4):
played the entire **Lust For Life** album (Iggy Pop, 9 tracks) at 3% volume —
`state: PLAYING`, position advancing. Recipe (accepted on the first try):
```python
URI  = f"x-sonosapi-hls-static:{tid}?sid=284&flags=8&sn=3"
meta = DIDL(item id=f"00032020{tid}" parentID="00020000" class=musicTrack + cdudn-desc)
dev.avTransport.AddURIToQueue([('InstanceID',0),('EnqueuedURI',URI),
    ('EnqueuedURIMetaData',meta),('DesiredFirstTrackNumberEnqueued',0),('EnqueueAsNext',0)])
dev.play_from_queue(0)      # → NumTracksAdded/NewQueueLength, then it plays
```
No `getMediaURI` call is needed — the static URI + `cdudn` are resolved on the speaker at start.

### 6.1. Endless radio / stations (track radio, Artist Radio)

YT Music also serves **endless stations** — "track radio" and "artist radio".
These play differently from a single track.

**Where to get a station seed:**
- Track radio: `getExtendedMetadata(<trackId>)` → a `<relatedPlay>` node with
  `<itemType>program</itemType>` and a long (~72-char) `programId`.
- Artist radio/shuffle: an artist page exposes "Artist Radio" / "Artist Shuffle" nodes
  (`itemType=playlist`, `canEnumerate=false`, `canPlay=true` — the list is infinite, play-only).

**Important:** a station is **NOT** resolvable via `getMediaURI`/`getMediaMetadata`
(the server returns "entity name not supported for playback" / treats it as a `PLAYLIST`).
The speaker streams it itself from the radio URI scheme.

**✅ Working recipe (accepted on the first try, `try_radio.py`):**
```
URI:    x-sonosapi-radio:<programId>?sid=284&flags=8300&sn=3
DIDL:   <item id="100c206c<programId>" parentID="-1" restricted="true">
          <upnp:class>object.item.audioItem.audioBroadcast.#station</upnp:class>
          <desc id="cdudn" …>SA_RINCON72711_X_#Svc72711-<hhsfx>-Token</desc>
        </item>
method: AVTransport#SetAVTransportURI  (NOT AddURIToQueue!) → Play
```
The speaker then self-feeds concrete `x-sonosapi-hls-static:` tracks.
Verified: Teardrop radio → `PLAYING`, Massive Attack + related.

Difference from a single track: track = `x-sonosapi-hls-static:…flags=8` + `AddURIToQueue`;
station = `x-sonosapi-radio:…flags=8300` + `SetAVTransportURI`.

---

## 7. Implications for Home Assistant

1. **Why `soco` got a 403:** its AppLink hit the SMAPI endpoint **without**
   `X-Goog-Api-Key` and without the proper flow. The key and protocol are now known.
2. **Browse/search directly:** reproduce the POST to
   `https://music.googleapis.com/v1:sendRequest` with `X-Goog-Api-Key` + a valid
   `Bearer` + an SMAPI body (`getMetadata`/`search`).
3. **Token refresh — solved (§10):** the `Bearer ya29…` lives ~1 hour but is obtained
   automatically via the SMAPI `refreshAuthToken` call from the durable `<key>`. The app
   is not needed for this — the PoC does it itself.
4. **Playback — verified (§6):** `AddURIToQueue` on :1400 with the short track id actually
   plays (the full loop confirmed live).
5. **Bottom line:** all three links (browse/search + refresh + playback) were reproduced
   by our own code without the app. For HA only the packaging remains. An alternative for
   browsing — **Music Assistant** (YT Music provider + Sonos player).

---

## 8. Security

- The capture contains a **live OAuth token and API keys**. In this file they are **masked**.
  The raw dump `muse_plain.bin` existed only in the ephemeral session scratchpad.
- The `Bearer ya29…` expires on its own after ~1 hour.
- The original `/Applications/Sonos.app` was never modified; the patched copy lives only in the scratchpad.
- Publishing/forwarding the raw dump or the keys is not allowed.

---

## 9. Identifiers (reference)

| Field | Value |
|---|---|
| Household | `Sonos_<HOUSEHOLD>` |
| Player (RINCON) | `RINCON_<MAC>01400` |
| SMAPI service id | `284` (YouTube Music), serial `sn=3` |
| loginToken householdId | `Sonos_<HOUSEHOLD>_<hhsfx>` |
| cdudn token | `SA_RINCON72711_X_#Svc72711-<hhsfx>-Token` |
| X-Sonos-Api-Key | `85f746ce-7307-4acf-bc36-71c9979d7b00` |
| mbedtls_ssl_write | `MAIN+0xc0a740` (base `0x10ed48000` on that run) |
| mbedtls_ssl_read | `≈ MAIN+0xc0c2e0` |

---

## 10. Where the tokens come from (origin)

Three tokens of different natures:

**`X-Goog-Api-Key: AIza…` — the shared Sonos↔YouTube Music integration key.**
- Not present in plaintext in the app/bundle.
- Arrives **encrypted** in the service manifest (`284-manifest`, field `apiKey.cr`/`apiKey.zp`;
  `cr` for the controller, `zp` for the speaker). The manifest is fetched from `cf.ws.sonos.com`.
- The app decrypts `cr` at runtime. We did NOT break the decryption scheme — and don't need to:
  the ready key was caught by the `mbedtls_ssl_write` hook.
- Changes very rarely (a change would break every old app) → the most stable part.

**`X-Sonos-Api-Key: 85f746ce-7307-4acf-bc36-71c9979d7b00` — a static app key** (constant).

**`Bearer ya29…` — an OAuth access token, minted from a refresh_token. ✅ MECHANISM CAUGHT LIVE (2026-11-25).**

Key finding: the refresh is **NOT** a direct Google OAuth2 call (`oauth2.googleapis.com/token`).
It is an ordinary **SMAPI action on the same endpoint** as browsing:
```
POST https://music.googleapis.com/v1:sendRequest
SOAPACTION: "http://www.sonos.com/Services/1.1#refreshAuthToken"
Headers: X-Goog-Api-Key + X-Sonos-Api-Key   ← without the second one the server returns res:1037 (fail)
Body (SOAP, credentials/loginToken):
    <token> = old (expired) ya29
    <key>   = base64(protobuf) — the DURABLE secret (see below)
Response: <refreshAuthTokenResult>
            <authToken>ya29…</authToken>     ← fresh Bearer (~1 hour)
            <privateKey>…</privateKey>       ← the same <key> (in case of rotation)
```

**Structure of `<key>`/`<privateKey>`** — a protobuf wrapping the Google refresh_token:
```
field 1 (bytes, 103 B): "1//0…"        ← Google refresh token (long-lived)
field 2 (varint):       <timestamp ms> ← account-link moment
```
So the whole refresh cycle is **self-contained within SMAPI** — the app does not call Google
OAuth directly; it hands the refresh blob to the Google proxy (`music.googleapis.com`), which
returns a fresh ya29.

Full chain:
```
RSonosGetDeviceAuthTokenOp   one-time account link (AppLink): Google login →
                             Sonos obtains a long-lived refresh_token (inside the <key> blob)
      ↓ (stored in the household — on the speaker; on the Mac it can be read from the refresh request)
refreshAuthToken (SMAPI)      <key> + old ya29 → fresh ya29 (~1 hour)
      ↓
Bearer ya29…  → sent to getMetadata/search on music.googleapis.com
```
Sonos auth endpoints in the binary (for the initial link): `sve.sslauth.sonos.com`,
`thor.ws.sonos.com/authz/v1/role/households/`.

"Fragility" in ascending order: **API key** (almost never) → **`<key>`/refresh_token** (on re-link) →
**ya29 access token** (every hour, obtained automatically from `<key>`).

> ✅ Confirmed: given `<key>` + `X-Goog-Api-Key`, you can mint a fresh ya29 yourself via
> `refreshAuthToken` (HTTP 200). The app is no longer needed for it — see §11.

---

## 11. Proof-of-Concept: browsing YouTube Music

A working **standalone** PoC (`ytmusic_standalone.py`): browses/searches the YouTube Music
catalog like the app, and **mints a fresh ya29 itself** via `refreshAuthToken` — the
capture/`muse_plain.bin` is NO longer needed. It only needs a small `sonos_creds.json`
config with the durable values:
```jsonc
{
  "x_goog_api_key":  "<Sonos's Google integration key, AIza…>",
  "x_sonos_api_key": "85f746ce-7307-4acf-bc36-71c9979d7b00",   // public constant
  "private_key":     "<base64 <key> blob: protobuf with refresh_token>",
  "household_id":    "Sonos_…",
  "device_id":       "XX-XX-XX-XX-XX-XX:B"
}
```
The fresh `ya29` is cached in `.ya29_cache` with a ~55-min TTL and re-minted automatically
on expiry or on a 401. So the PoC runs on its own, without a running Sonos app.

### Results (live account catalog, run WITHOUT any capture)
```
refresh:         fresh ya29 minted (261 chars), valid ~54 min   ← obtained the token itself
ROOT:            Home · Library · My Supermix
  → Library:     Playlists · Albums · Songs · Artists · Subscriptions · Podcasts
SEARCH "mogwai": Mogwai · Mogwai Beach Club · 808 MOGWAI · Iggy Pop
```
Every call returned HTTP 200 with real data → protocol and refresh fully reproduced.
(Note: child-node ids are the full ~60-char `ALkSOi…`; a truncated id → `Malformed resource name`.)

### Code (`ytmusic_standalone.py`)
```python
#!/usr/bin/env python3
"""
Standalone YouTube-Music-on-Sonos PoC — NO capture file needed.

It needs only durable credentials in sonos_creds.json (next to this script):
  {
    "x_goog_api_key":  "<Sonos's Google API key>",
    "x_sonos_api_key": "85f746ce-7307-4acf-bc36-71c9979d7b00",
    "private_key":     "<base64 refresh-token blob, SMAPI <key>/<privateKey>>",
    "household_id":    "Sonos_xxx_xxxxxxxx",
    "device_id":       "XX-XX-XX-XX-XX-XX:B"
  }
The short-lived ya29 Bearer is minted on demand via SMAPI refreshAuthToken and
cached in .ya29_cache (with expiry), so the Sonos app never has to run.

Usage:
  ytmusic_standalone.py                 # browse root
  ytmusic_standalone.py browse LIBRARY  # browse a node id
  ytmusic_standalone.py search ARTISTS mogwai
  ytmusic_standalone.py refresh         # force a token refresh
"""
import sys, os, json, re, gzip, time, html, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
CFG  = os.path.join(HERE, "sonos_creds.json")
CACHE= os.path.join(HERE, ".ya29_cache")
ENDPOINT = "https://music.googleapis.com/v1:sendRequest"
NS = "http://www.sonos.com/Services/1.1"

def cfg():
    return json.load(open(CFG))

def post(soapaction, header_inner, body_inner, bearer=None):
    c = cfg()
    env = (f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
           f'<s:Header>{header_inner}'
           f'<context xmlns="{NS}"><timeZone>+2:00</timeZone></context>'
           f'</s:Header><s:Body>{body_inner}</s:Body></s:Envelope>').encode()
    req = urllib.request.Request(ENDPOINT, data=env, method="POST")
    req.add_header("Host", "music.googleapis.com")
    req.add_header("X-Goog-Api-Key", c["x_goog_api_key"])
    req.add_header("X-Sonos-Api-Key", c["x_sonos_api_key"])
    if bearer:
        req.add_header("Authorization", "Bearer " + bearer)
    req.add_header("Content-Type", 'text/xml; charset="utf-8"')
    req.add_header("Accept-Encoding", "gzip")
    req.add_header("User-Agent", "Linux UPnP/1.0 Sonos/90.0-82050 (MDCR_PoC)")
    req.add_header("SOAPACTION", f'"{NS}#{soapaction}"')
    try:
        resp = urllib.request.urlopen(req, timeout=15); raw = resp.read(); code = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read(); code = e.code
    if raw[:2] == b"\x1f\x8b": raw = gzip.decompress(raw)
    return code, raw.decode("utf-8", "replace")

def do_refresh():
    """Mint a fresh ya29 from the durable private_key. Returns (token, expires_at)."""
    c = cfg()
    hdr = (f'<credentials xmlns="{NS}">'
           f'<deviceId>{c["device_id"]}</deviceId><deviceProvider>Sonos</deviceProvider>'
           f'<loginToken><key>{c["private_key"]}</key>'
           f'<householdId>{c["household_id"]}</householdId></loginToken></credentials>')
    code, xml = post("refreshAuthToken", hdr,
                     f'<refreshAuthToken xmlns="{NS}"></refreshAuthToken>')
    m = re.search(r"<authToken>(ya29\.[^<]+)</authToken>", xml)
    if not m:
        sys.exit(f"refresh failed (HTTP {code}): {xml[:300]}")
    tok = m.group(1)
    # also persist any rotated privateKey back to the config
    pk = re.search(r"<privateKey>([^<]+)</privateKey>", xml)
    if pk and pk.group(1) != c["private_key"]:
        c["private_key"] = pk.group(1); json.dump(c, open(CFG, "w"), indent=2)
    exp = time.time() + 55*60   # ya29 lives ~1h; refresh a bit early
    json.dump({"token": tok, "exp": exp}, open(CACHE, "w"))
    return tok, exp

def token():
    """Return a valid ya29, refreshing (and caching) only when needed."""
    if os.path.exists(CACHE):
        d = json.load(open(CACHE))
        if d.get("exp", 0) > time.time() + 30:
            return d["token"]
    tok, _ = do_refresh()
    return tok

def credentials_header():
    c = cfg()
    return (f'<credentials xmlns="{NS}">'
            f'<loginToken><householdId>{c["household_id"]}</householdId></loginToken>'
            f'<deviceId>{c["device_id"]}</deviceId><deviceProvider>Sonos</deviceProvider>'
            f'</credentials>')

def smapi(soapaction, body_inner):
    """Call a catalog action, auto-refreshing the Bearer on 401."""
    for attempt in (1, 2):
        tok = token()
        code, xml = post(soapaction, credentials_header(), body_inner, bearer=tok)
        if code == 401 and attempt == 1:
            if os.path.exists(CACHE): os.remove(CACHE)   # force refresh, retry once
            continue
        return code, xml
    return code, xml

def pretty(xml):
    xml = html.unescape(html.unescape(xml))
    items = re.findall(r"<(mediaCollection|mediaMetadata)>(.*?)</\1>", xml, re.S)
    if not items:
        print(xml[:1200]); return
    print(f"-- {len(items)} items --")
    def g(blob, tag):
        m = re.search(rf"<{tag}>([^<]*)</{tag}>", blob); return m.group(1) if m else ""
    for kind, blob in items:
        k = "DIR " if kind == "mediaCollection" else "track"
        title  = g(blob, "title")
        itype  = g(blob, "itemType") or g(blob, "mimeType")
        artist = g(blob, "artist")
        iid    = g(blob, "id")
        extra  = f" — {artist}" if artist else ""
        print(f"  [{k}] {title+extra:<42.42} ({itype:<10}) id={iid}")

def main():
    a = sys.argv[1:]
    if a and a[0] == "refresh":
        tok, exp = do_refresh()
        print(f"fresh ya29 minted ({len(tok)} chars), valid ~{int((exp-time.time())/60)} min"); return
    if not a or a[0] == "browse":
        node = a[1] if len(a) > 1 else "root"
        print(f"== getMetadata {node} ==")
        code, xml = smapi("getMetadata",
            f'<getMetadata xmlns="{NS}"><id>{node}</id><index>0</index><count>50</count></getMetadata>')
        print("HTTP", code); pretty(xml)
    elif a[0] == "search":
        cat, term = a[1], " ".join(a[2:])
        print(f"== search {cat} '{term}' ==")
        code, xml = smapi("search",
            f'<search xmlns="{NS}"><id>{cat}</id><term>{html.escape(term)}</term><index>0</index><count>50</count></search>')
        print("HTTP", code); pretty(xml)

if __name__ == "__main__":
    main()
```

---

## 12. Status and next steps

**Research complete (2026-11-25).**

Done:
- ✅ Full architecture map (4 channels, mbedTLS).
- ✅ Decryption of the Muse/SMAPI traffic (Frida + mbedTLS hook).
- ✅ YouTube Music browse/search protocol reproduced in the PoC.
- ✅ **`ya29` refresh mechanism caught live** — it's the SMAPI `refreshAuthToken`, not a direct
  Google OAuth2; `<key>` = a protobuf with the refresh_token (§10).
- ✅ **Standalone PoC** (`ytmusic_standalone.py`): mints ya29 from `<key>` itself,
  caches it, browses/searches the catalog — the running app is no longer needed (§11).
- ✅ Track playback via local UPnP (fields in §6).

Everything needed for a standalone Home Assistant integration is now known. Only
engineering remains (not reversing):
1. **Browse/search** — direct SMAPI from `ytmusic_standalone.py` (done).
2. ✅ **Playback** — `AddURIToQueue` on :1400 assembled and **verified live** (§6,
   `play_album.py`): the whole Lust For Life album played at 3% volume.
3. (opt.) **Decrypt `apiKey.cr` from the manifest** — so `x_goog_api_key` is obtained
   automatically instead of being written into the config (not a blocker now: the key changes very rarely).
4. Package into an HA integration / `custom_component`. A pragmatic alternative for browsing —
   Music Assistant (YT Music via `ytmusicapi`) + local UPnP for playback.

Durable credentials (needed by the PoC): `x_goog_api_key`, `private_key` (the `<key>` blob),
`household_id`, `device_id`. `x_sonos_api_key` is a public constant. They live in
`sonos_creds.json` (scratchpad, do NOT commit/publish — it contains the refresh_token).

Session files (ephemeral scratchpad, with live creds — do not keep/publish):
`SonosPatched.app`, `tap.js`, `driver.py`, `mbed_discover.py`, `mbed_capture.py`,
`refresh_capture.py`, `refresh_poc.py`, `muse_plain.bin`, `refresh_plain.bin`,
`sonos_creds.json`, `ytmusic_poc.py`, `ytmusic_standalone.py`, `play_album.py`, `h2parse.py`.
