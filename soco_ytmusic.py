#!/usr/bin/env python3
"""
soco_ytmusic — YouTube Music (SMAPI sid=284) support layered on top of SoCo,
WITHOUT forking the library. Subclasses SoCo's MusicServiceSoapClient to add the
YT-Music-specific authentication and SOAP handling, and MusicService to wire it in.

Requirements:
  - soco
  - sonos_creds.json (generated via extract_apikey.py)
"""
import os, re, json, time, sys, html
import soco
from soco.music_services.music_service import MusicService, MusicServiceSoapClient
from soco.soap import SoapMessage, SoapFault
import soco.soap as _soap

HERE  = os.path.dirname(os.path.abspath(__file__))
CFG   = os.path.join(HERE, "sonos_creds.json")
CACHE = os.path.join(HERE, ".ya29_cache")
NS    = "http://www.sonos.com/Services/1.1"

# ---------------------------------------------------------------------------
# Part A: tolerant fault handling
# ---------------------------------------------------------------------------
_LAST_RAW = {"data": None}

if not getattr(_soap.XML, "_ytm_spy", False):
    _orig_fromstring = _soap.XML.fromstring
    def _spy_fromstring(text, *a, **k):
        _LAST_RAW["data"] = text
        return _orig_fromstring(text, *a, **k)
    _soap.XML.fromstring = _spy_fromstring
    _soap.XML._ytm_spy = True

_FAULT_RE = re.compile(r"<faultstring>(.*?)</faultstring>", re.S)
_AUTH_MARKERS = ("TokenRefreshRequired", "AuthTokenExpired", "res:1035",
                 "res:1036", "NOT_LINKED", "UNAUTHENTICATED")


class YTMusicFault(Exception):
    """Application-level fault returned by the YouTube Music SMAPI service."""
    def __init__(self, message, raw=None):
        self.message, self.raw = message, raw
        super().__init__(message)


def _classify_fault(raw):
    """Extract and classify fault message textually so malformed XML doesn't crash."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = _FAULT_RE.search(raw)
    if not m:
        return None
    fs = html.unescape(m.group(1))
    if any(w in fs for w in _AUTH_MARKERS):
        return ("AUTH", fs)
    detail = re.search(r"Malformed resource name \[[^\]]*\]", fs)
    if detail is None:
        detail = re.search(r"BadRequestException: [^;<\n]{0,120}"
                           r"|[A-Za-z]+Exception: [^;<\n]{0,120}", fs)
    code = re.search(r"INVALID_ARGUMENT|NOT_FOUND|PERMISSION_DENIED"
                     r"|FAILED_PRECONDITION|res:\d+", fs)
    parts = [p for p in (code.group(0) if code else None,
                         detail.group(0).strip() if detail else None) if p]
    return ("APP", " — ".join(parts) if parts else fs.strip()[:160])


# ---------------------------------------------------------------------------
# Account detection: the account serial (sn=N) and the cdudn tag are specific
# to each household's YouTube Music link. Read them from the speaker's own
# favorites/queue, where any YT Music item already carries both.
# ---------------------------------------------------------------------------
SID = "284"
_SN_RE    = re.compile(r"sid=" + SID + r"&[^\"<\s]*?sn=(\d+)")
_CDUDN_RE = re.compile(r"SA_RINCON(\d+)_X_#Svc\1-([^<\s-]+)-Token")


def detect_account(device):
    """Return {'sn': str|None, 'cdudn': str|None} found on the speaker."""
    found = {"sn": None, "cdudn": None}
    for oid in ("FV:2", "Q:0"):
        try:
            r = device.contentDirectory.Browse([
                ("ObjectID", oid), ("BrowseFlag", "BrowseDirectChildren"),
                ("Filter", "*"), ("StartingIndex", 0), ("RequestedCount", 500),
                ("SortCriteria", "")])
        except Exception:
            continue
        x = html.unescape(r.get("Result", ""))
        if not found["sn"]:
            m = _SN_RE.search(x)
            if m:
                found["sn"] = m.group(1)
        if not found["cdudn"]:
            m = _CDUDN_RE.search(x)
            if m and m.group(1) == str(int(SID) * 256 + 7):
                found["cdudn"] = m.group(0)
        if found["sn"] and found["cdudn"]:
            break
    return found


def cdudn_suffix(cdudn):
    m = _CDUDN_RE.search(cdudn or "")
    return m.group(2) if m else None


class YouTubeMusicSoapClient(MusicServiceSoapClient):
    """MusicServiceSoapClient implementing YT Music's OAuth2-Bearer dialect."""

    def __init__(self, *args, creds, **kwargs):
        super().__init__(*args, **kwargs)
        self.creds = creds
        self._device_id    = creds.get("device_id", "")
        self._household_id = creds.get("household_id", "")
        self.http_headers["X-Goog-Api-Key"]  = creds.get("x_goog_api_key", "")
        self.http_headers["X-Sonos-Api-Key"] = creds.get("x_sonos_api_key", "85f746ce-7307-4acf-bc36-71c9979d7b00")

    def get_soap_header(self):
        if self._cached_soap_header is not None:
            return self._cached_soap_header
        hdr = (f'<credentials xmlns="{NS}">'
               f'<deviceId>{self._device_id}</deviceId>'
               f'<deviceProvider>Sonos</deviceProvider>'
               f'<loginToken><householdId>{self._household_id}</householdId></loginToken>'
               f'</credentials>'
               f'<context xmlns="{NS}"><timeZone>+00:00</timeZone></context>')
        self._cached_soap_header = hdr
        return hdr

    def _cached_token(self):
        if os.path.exists(CACHE):
            try:
                with open(CACHE, "r") as f:
                    d = json.load(f)
                if d.get("exp", 0) > time.time() + 30:
                    return d["token"]
            except Exception:
                pass
        return None

    def _bearer(self):
        tok = self._cached_token()
        if tok:
            return tok
        if self.creds.get("private_key"):
            return self._refresh()
        raise RuntimeError("No valid ya29 token and no private_key in sonos_creds.json.\n"
                           "Run extract_apikey.py to extract credentials from Sonos.")

    def _refresh(self):
        """SMAPI refreshAuthToken: loginToken{token,key,householdId}, NO Bearer header."""
        if not self.creds.get("private_key"):
            raise RuntimeError("Cannot refresh token: private_key (<key>) is missing in sonos_creds.json")
        old = self._cached_token() or ""
        refresh_header = (
            f'<credentials xmlns="{NS}">'
            f'<deviceId>{self._device_id}</deviceId><deviceProvider>Sonos</deviceProvider>'
            f'<loginToken><token>{old}</token><key>{self.creds["private_key"]}</key>'
            f'<householdId>{self._household_id}</householdId></loginToken></credentials>')
        headers = {k: v for k, v in self.http_headers.items() if k.lower() != "authorization"}
        msg = SoapMessage(
            endpoint=self.endpoint, method="refreshAuthToken", parameters=[],
            http_headers=headers,
            soap_action=f"{NS}#refreshAuthToken",
            soap_header=refresh_header, namespace=NS, timeout=self.timeout)
        result = msg.call()
        tok = _find(result, "authToken")
        key = _find(result, "privateKey")
        if not tok:
            raise RuntimeError(f"refreshAuthToken returned no authToken: {result}")
        if key and key != self.creds.get("private_key"):
            self.creds["private_key"] = key
            with open(CFG, "w") as f:
                json.dump(self.creds, f, indent=2)
        with open(CACHE, "w") as f:
            json.dump({"token": tok, "exp": time.time() + 55 * 60}, f)
        return tok

    def call(self, method, args=None):
        _LAST_RAW["data"] = None
        self.http_headers["Authorization"] = "Bearer " + self._bearer()
        try:
            return super().call(method, args)
        except Exception as exc:
            kind = _classify_fault(_LAST_RAW.get("data"))
            if kind and kind[0] == "APP":
                raise YTMusicFault(kind[1], _LAST_RAW.get("data")) from None
            if ((kind and kind[0] == "AUTH") or _looks_like_auth(exc)) and self.creds.get("private_key"):
                if os.path.exists(CACHE):
                    try: os.remove(CACHE)
                    except OSError: pass
                self.http_headers["Authorization"] = "Bearer " + self._refresh()
                return super().call(method, args)
            raise


class YouTubeMusic(MusicService):
    """soco MusicService wired to the YouTube Music Bearer client."""

    @classmethod
    def get_data_for_name(cls, service_name):
        try:
            return super().get_data_for_name(service_name)
        except Exception:
            return {
                'Id': '284', 'Name': 'YouTube Music', 'Version': '1.1',
                'Uri': 'https://music.googleapis.com/v1:sendRequest',
                'SecureUri': 'https://music.googleapis.com/v1:sendRequest',
                'ContainerType': 'MService', 'Capabilities': '32473609',
                'Auth': 'AppLink', 'PollInterval': '60',
                'ManifestUri': 'https://cf.ws.sonos.com/p/m/a3fd2ecc-6039-47fe-8ced-1939e070c432',
                'ServiceID': '284', 'ServiceType': '72711'
            }

    def __init__(self, creds=None, device=None, token_store=None):
        if creds is None:
            if not os.path.exists(CFG):
                raise FileNotFoundError(
                    f"Configuration file {CFG} not found.\n"
                    "Please run extract_apikey.py while Sonos is running to extract credentials.")
            with open(CFG, "r") as f:
                creds = json.load(f)
        self._creds = creds
        super().__init__("YouTube Music", token_store=token_store, device=device)
        self.soap_client = YouTubeMusicSoapClient(
            endpoint=self.secure_uri, timeout=12, music_service=self,
            token_store=self.token_store, device=device, creds=creds)

    def browse(self, node="root", index=0, count=50):
        res = self.soap_client.call("getMetadata",
            [("id", node), ("index", index), ("count", count)])
        return _items(res)

    def search(self, category, term, index=0, count=50):
        res = self.soap_client.call("search",
            [("id", category), ("term", term), ("index", index), ("count", count)])
        return _items(res)

    def track_radio(self, track_id):
        """Return the programId for starting radio from this track, or None."""
        res = self.soap_client.call("getExtendedMetadata", [("id", track_id)])
        rp = _get(res, "relatedPlay")
        return _find(rp, "id") if rp is not None else None

    def resolve_track(self, track_id):
        res = self.soap_client.call("getExtendedMetadata", [("id", track_id)])
        mm = _get(res, "mediaMetadata")
        return {"id": _find(mm, "id"), "title": _find(mm, "title"),
                "artist": _find(mm, "artist"), "album": _find(mm, "album"),
                "artistId": _find(mm, "artistId"), "albumId": _find(mm, "albumId")}

    def artist_id_of_track(self, track_id):
        res = self.soap_client.call("getExtendedMetadata", [("id", track_id)])
        return _find(res, "artistId")

    def resolve_artist(self, name):
        for al in self.search("ALBUMS", name, count=6):
            if al.get("itemType") != "album":
                continue
            tracks = [t for t in self.browse(al["id"], count=5)
                      if t.get("itemType") == "track"]
            if tracks:
                aid = self.artist_id_of_track(tracks[0]["id"])
                if aid:
                    return aid
        return None

    def artist_node(self, artist_id, which="Top Songs"):
        for it in self.browse(artist_id, count=40):
            if (it.get("title") or "").strip().lower() == which.lower():
                return it["id"]
        return None

    def artist_top_tracks(self, artist_id, count=20, resolve=True):
        node = self.artist_node(artist_id, "Top Songs")
        if not node:
            return []
        raw = [t for t in self.browse(node, count=count)
               if t.get("itemType") == "track"]
        if not resolve:
            return raw
        out, seen = [], set()
        for t in raw:
            r = self.resolve_track(t["id"])
            if r.get("id") and r["id"] not in seen:
                seen.add(r["id"])
                out.append(r)
        return out

    # ---------- playback ----------
    def _account(self, device):
        """Resolve sn + cdudn: sonos_creds.json first, then the speaker."""
        if getattr(self, "_acct", None):
            return self._acct
        sn, cd = self._creds.get("sn"), self._creds.get("cdudn")
        if (not sn or not cd) and device is not None:
            det = detect_account(device)
            sn, cd = sn or det["sn"], cd or det["cdudn"]
        if not cd:
            suffix = None
            hh = self._creds.get("household_id", "")
            if "_" in hh[len("Sonos_"):]:
                suffix = hh.rsplit("_", 1)[-1]
            if suffix:
                st = self.service_type
                cd = f"SA_RINCON{st}_X_#Svc{st}-{suffix}-Token"
        if not sn or not cd:
            raise RuntimeError(
                "Could not determine this household's YouTube Music account "
                f"(sn={sn!r}, cdudn={cd!r}).\n"
                "Fix: in the Sonos app, play any YouTube Music song on this speaker "
                "(or add one to Sonos Favorites), then retry — or re-run extract_apikey.py, "
                "or set \"sn\"/\"cdudn\" in sonos_creds.json manually.")
        self._acct = (str(sn), cd)
        return self._acct

    def _didl(self, item_id, cls, cdudn, title, artist="", album=""):
        esc = lambda s: html.escape(s or "", quote=True)
        return ('<DIDL-Lite xmlns:dc="http://purl.org/dc/elements/1.1/" '
                'xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" '
                'xmlns:r="urn:schemas-rinconnetworks-com:metadata-1-0/" '
                'xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/">'
                f'<item id="{item_id}" parentID="-1" restricted="true">'
                f'<dc:title>{esc(title)}</dc:title><upnp:class>{cls}</upnp:class>'
                f'<dc:creator>{esc(artist)}</dc:creator><upnp:album>{esc(album)}</upnp:album>'
                f'<desc id="cdudn" nameSpace="urn:schemas-rinconnetworks-com:metadata-1-0/">'
                f'{cdudn}</desc></item></DIDL-Lite>')

    def play_tracks(self, device, tracks, volume=None):
        """Replace the queue with `tracks` (each {'id','title','artist'}) and play."""
        if not tracks:
            raise ValueError("No tracks provided to play_tracks()")
        if volume is not None:
            device.volume = volume
        sn, cdudn = self._account(device)
        try:
            device.stop()
        except Exception:
            pass
        try:
            device.clear_queue()
        except Exception:
            pass
        first_track_idx = 0
        for i, t in enumerate(tracks):
            uri = f"x-sonosapi-hls-static:{t['id']}?sid={SID}&flags=8&sn={sn}"
            meta = self._didl("00032020" + t["id"],
                              "object.item.audioItem.musicTrack", cdudn,
                              t.get("title", ""), t.get("artist", ""), t.get("album", ""))
            res = device.avTransport.AddURIToQueue([
                ("InstanceID", 0), ("EnqueuedURI", uri), ("EnqueuedURIMetaData", meta),
                ("DesiredFirstTrackNumberEnqueued", 0), ("EnqueueAsNext", 0)])
            if i == 0 and res and "FirstTrackNumberEnqueued" in res:
                try:
                    first_track_idx = int(res["FirstTrackNumberEnqueued"]) - 1
                except Exception:
                    pass
        device.play_from_queue(first_track_idx)
        return device.get_current_track_info()

    def play_station(self, device, program_id, title="Radio", volume=None):
        """Start an endless station (track-radio programId or Artist Radio id)."""
        if volume is not None:
            device.volume = volume
        sn, cdudn = self._account(device)
        uri = f"x-sonosapi-radio:{program_id}?sid={SID}&flags=8300&sn={sn}"
        meta = self._didl("100c206c" + program_id,
                          "object.item.audioItem.audioBroadcast.#station", cdudn, title)
        device.avTransport.SetAVTransportURI([
            ("InstanceID", 0), ("CurrentURI", uri), ("CurrentURIMetaData", meta)])
        device.play()
        return device.get_current_track_info()


# ---------- helpers ----------
def _is_elem(o):
    return hasattr(o, "iter") and hasattr(o, "tag")

def _ln(elem):
    return elem.tag.rsplit("}", 1)[-1]

def _find(o, key):
    if _is_elem(o):
        for e in o.iter():
            if _ln(e) == key and e.text:
                return e.text
        return None
    if isinstance(o, dict):
        for k, v in o.items():
            if k == key and isinstance(v, str):
                return v
            r = _find(v, key)
            if r is not None:
                return r
    elif isinstance(o, (list, tuple)):
        for v in o:
            r = _find(v, key)
            if r is not None:
                return r
    return None

def _get(o, key):
    if _is_elem(o):
        for e in o.iter():
            if _ln(e) == key:
                return e
        return None
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            r = _get(v, key)
            if r is not None:
                return r
    elif isinstance(o, (list, tuple)):
        for v in o:
            r = _get(v, key)
            if r is not None:
                return r
    return None

def _mk(flat):
    return {
        "title":        flat.get("title"),
        "id":           flat.get("id"),
        "itemType":     flat.get("itemType") or flat.get("mimeType"),
        "artist":       flat.get("artist"),
        "duration":     flat.get("duration"),
        "canEnumerate": flat.get("canEnumerate"),
    }

def _items(o):
    out = []
    if _is_elem(o):
        for e in o.iter():
            if _ln(e) not in ("mediaCollection", "mediaMetadata"):
                continue
            flat = {}
            for c in e.iter():
                t = _ln(c)
                if c.text and c.text.strip() and t not in flat:
                    flat[t] = c.text.strip()
            out.append(_mk(flat))
    else:
        def walk(x):
            if isinstance(x, dict):
                if x.get("id") and x.get("title") and (x.get("itemType") or x.get("mimeType")):
                    tm = x.get("trackMetadata") if isinstance(x.get("trackMetadata"), dict) else {}
                    out.append(_mk({
                        "title": x.get("title"), "id": x.get("id"),
                        "itemType": x.get("itemType"), "mimeType": x.get("mimeType"),
                        "artist": (tm or {}).get("artist") or x.get("artist"),
                        "duration": (tm or {}).get("duration"),
                        "canEnumerate": x.get("canEnumerate"),
                    }))
                for v in x.values():
                    walk(v)
            elif isinstance(x, (list, tuple)):
                for v in x:
                    walk(v)
        walk(o)
    return out

def _looks_like_auth(exc):
    s = (str(getattr(exc, "faultcode", "")) + " " + str(exc)).lower()
    return any(w in s for w in ("auth", "token", "401", "unauthor", "expired"))


def get_device(speaker_target=None):
    target = speaker_target or os.environ.get("SONOS_SPEAKER")
    if target:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return soco.SoCo(target)
        for s in (soco.discover(timeout=3) or []):
            if s.player_name.lower() == target.lower():
                return s
        return soco.SoCo(target)
    # Default to auto-discovery
    discovered = list(soco.discover(timeout=3) or [])
    if discovered:
        return discovered[0]
    raise RuntimeError("No Sonos speaker specified and auto-discovery found none.\n"
                       "Pass --speaker <IP_OR_NAME> or set the SONOS_SPEAKER environment variable.")


# ---------------- CLI ----------------
def print_help():
    print("""
Usage: soco_ytmusic.py [options] <command> [arguments]

Commands:
  play <query>              Search song, queue it and play immediately
  album <name>              Find album, queue all tracks and play
  artist <name>             Find artist, queue top songs and play
  station <query|id>        Start endless radio station for track or artist
  search <cat> <query>      Search catalog (SONGS, ALBUMS, ARTISTS, PLAYLISTS)
  browse [node_id]          Browse node (default: root)
  pause                     Pause current playback
  resume                    Resume playback
  next                      Skip to next track
  prev                      Previous track
  stop                      Stop playback
  info                      Show currently playing track info
  volume [0-100]            Get or set volume
  speakers                  Discover and list Sonos speakers on the network

Options:
  --speaker <ip_or_name>    Target speaker (or set SONOS_SPEAKER)
""")


def main():
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--speaker", default=None, help="Speaker IP or name")
    parser.add_argument("cmd", nargs="?", default="help")
    parser.add_argument("args", nargs=argparse.REMAINDER)

    parsed, unknown = parser.parse_known_args()
    cmd = parsed.cmd.lower()
    extra = parsed.args

    if cmd in ("help", "-h", "--help"):
        print_help()
        return

    if cmd == "speakers":
        print("[*] Discovering Sonos speakers on network...")
        found = list(soco.discover(timeout=4) or [])
        if not found:
            print("No speakers discovered.")
            return
        for s in found:
            print(f"  • {s.player_name:<20} IP: {s.ip_address:<16} Household: {s.household_id}")
        return

    try:
        dev = get_device(parsed.speaker)
    except Exception as e:
        print(f"[!] Speaker error: {e}")
        return

    # Basic transport commands
    if cmd == "pause":
        dev.pause()
        print(f"Paused on {dev.player_name}")
        return
    elif cmd in ("resume", "unpause"):
        dev.play()
        print(f"Resumed playback on {dev.player_name}")
        return
    elif cmd == "stop":
        dev.stop()
        print(f"Stopped on {dev.player_name}")
        return
    elif cmd == "next":
        dev.next()
        print(f"Skipped to next on {dev.player_name}")
        return
    elif cmd in ("prev", "previous"):
        dev.previous()
        print(f"Previous track on {dev.player_name}")
        return
    elif cmd == "info":
        info = dev.get_current_track_info()
        vol = dev.volume
        print(f"Speaker:  {dev.player_name} (Volume: {vol}%)")
        print(f"State:    {dev.get_current_transport_info().get('current_transport_state')}")
        print(f"Track:    {info.get('title')}")
        print(f"Artist:   {info.get('artist')}")
        print(f"Album:    {info.get('album')}")
        print(f"Position: {info.get('position')} / {info.get('duration')}")
        return
    elif cmd == "volume":
        if extra:
            vol = int(extra[0])
            dev.volume = vol
            print(f"Volume set to {vol}% on {dev.player_name}")
        else:
            print(f"Current volume on {dev.player_name}: {dev.volume}%")
        return

    # YT Music SMAPI commands
    try:
        ym = YouTubeMusic(device=dev)
    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}")
        return
    except Exception as e:
        print(f"\n[!] Initialization error: {e}")
        return

    if cmd == "browse":
        node = extra[0] if extra else "root"
        print(f"== Browse node: {node} ==")
        items = ym.browse(node)
        for it in items:
            inf = []
            if it.get("artist"): inf.append(it["artist"])
            if it.get("canEnumerate") == "false": inf.append("STATION")
            tag = (" — " + ", ".join(inf)) if inf else ""
            print(f"  [{(it['itemType'] or ''):<10}] {(it['title'] or '')[:36]:<36}{tag:<22} id={it['id']}")

    elif cmd == "search":
        if not extra:
            print("Usage: soco_ytmusic.py search <SONGS|ALBUMS|ARTISTS|PLAYLISTS> <query>")
            return
        cat = extra[0].upper()
        if cat in ("TRACKS", "TRACK", "SONG"):
            cat = "SONGS"
        if cat not in ("SONGS", "ALBUMS", "ARTISTS", "PLAYLISTS"):
            cat = "SONGS"
            term = " ".join(extra)
        else:
            term = " ".join(extra[1:])
        print(f"== Search {cat}: '{term}' ==")
        items = ym.search(cat, term)
        for it in items:
            art = f" — {it['artist']}" if it.get("artist") else ""
            print(f"  [{(it['itemType'] or ''):<10}] {(it['title'] or '')[:36]:<36}{art:<24} id={it['id']}")

    elif cmd == "play":
        query = " ".join(extra).strip()
        if not query:
            dev.play()
            print(f"Resumed playback on {dev.player_name}")
            return
        print(f"[*] Searching for '{query}' on YouTube Music...")
        tracks = ym.search("SONGS", query, count=5)
        playable_tracks = []
        for t in tracks:
            resolved = ym.resolve_track(t["id"])
            if resolved.get("id"):
                playable_tracks.append(resolved)
                break
        if not playable_tracks:
            albums = ym.search("ALBUMS", query, count=3)
            if albums:
                alb_tracks = [t for t in ym.browse(albums[0]["id"], count=15) if t.get("itemType") == "track"]
                playable_tracks = alb_tracks
        if not playable_tracks:
            print(f"[!] No playable tracks found for '{query}'")
            return
        print(f"[*] Queueing: {playable_tracks[0].get('title')} — {playable_tracks[0].get('artist')} on {dev.player_name}")
        ym.play_tracks(dev, playable_tracks)
        print(f"[✓] Playing now! (Track: {playable_tracks[0].get('title')})")

    elif cmd == "artist":
        name = " ".join(extra).strip()
        if not name:
            print("Usage: soco_ytmusic.py artist <artist name>")
            return
        print(f"[*] Resolving artist '{name}'...")
        aid = ym.resolve_artist(name)
        if not aid:
            print(f"[!] Could not resolve artist '{name}'")
            return
        print(f"[*] Fetching top songs for artist (id={aid[:16]}...)...")
        top = ym.artist_top_tracks(aid, count=15)
        if not top:
            print(f"[!] No top songs found for artist '{name}'")
            return
        print(f"[*] Playing {len(top)} top songs by '{name}' on {dev.player_name}...")
        ym.play_tracks(dev, top)
        print(f"[✓] Playing now! ({top[0].get('title')})")

    elif cmd == "album":
        name = " ".join(extra).strip()
        if not name:
            print("Usage: soco_ytmusic.py album <album name>")
            return
        print(f"[*] Searching for album '{name}'...")
        albums = ym.search("ALBUMS", name, count=3)
        if not albums:
            print(f"[!] No albums found matching '{name}'")
            return
        alb = albums[0]
        print(f"[*] Fetching tracks for album '{alb.get('title')}' by {alb.get('artist')}...")
        tracks = [t for t in ym.browse(alb["id"], count=50) if t.get("itemType") == "track"]
        if not tracks:
            print(f"[!] No tracks found in album '{alb.get('title')}'")
            return
        print(f"[*] Queueing {len(tracks)} tracks from '{alb.get('title')}' on {dev.player_name}...")
        ym.play_tracks(dev, tracks)
        print(f"[✓] Playing now! (First track: {tracks[0].get('title')})")

    elif cmd == "station":
        query = " ".join(extra).strip()
        if not query:
            print("Usage: soco_ytmusic.py station <song / artist / programId>")
            return
        prog_id = None
        if query.startswith("ALkSOi") or len(query) > 50:
            prog_id = query
        else:
            print(f"[*] Finding radio station for '{query}'...")
            tracks = ym.search("SONGS", query, count=3)
            if tracks:
                prog_id = ym.track_radio(tracks[0]["id"])
            if not prog_id:
                aid = ym.resolve_artist(query)
                if aid:
                    prog_id = ym.artist_node(aid, "Artist Radio")
        if not prog_id:
            print(f"[!] Could not find radio station for '{query}'")
            return
        print(f"[*] Starting radio station on {dev.player_name}...")
        ym.play_station(dev, prog_id, title=f"{query} Radio")
        print(f"[✓] Radio station playing!")

    else:
        print_help()


if __name__ == "__main__":
    main()
