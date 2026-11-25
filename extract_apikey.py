#!/usr/bin/env python3
"""
extract_apikey.py — extract Sonos's Google credentials from the running app.

Extracts:
  * X-Goog-Api-Key  (the global "AIza..." Google API key Sonos uses for YouTube Music)
  * ya29...         (the live OAuth2 access token)
  * private_key     (the durable SMAPI <key> refresh blob containing Google refresh_token)
  * household_id    (Sonos_...)
  * device_id       (speaker device / MAC)

Optionally saves everything directly to sonos_creds.json so soco_ytmusic is immediately ready.
"""
import frida, sys, argparse, re, json, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CFG = os.path.join(HERE, "sonos_creds.json")
DEFAULT_CACHE = os.path.join(HERE, ".ya29_cache")

AP = argparse.ArgumentParser(description="Extract Sonos Google credentials from running Sonos app.")
AP.add_argument("--pid", type=int, default=None, help="attach to this pid")
AP.add_argument("--name", default="Sonos", help="process name to attach to (default: Sonos)")
AP.add_argument("--spawn", default=None, help="launch this binary under Frida instead of attaching")
AP.add_argument("--with-token", action="store_true", default=True, help="also extract live ya29 OAuth token (default: True)")
AP.add_argument("--no-save", action="store_true", help="do not write sonos_creds.json automatically")
AP.add_argument("--speaker", default=None, help="speaker IP or name for device info (optional auto-detect)")
AP.add_argument("--json", action="store_true", help="print results as JSON")
AP.add_argument("--listen", type=int, default=15, help="seconds to listen for live TLS requests via hook (default: 15s)")
args = AP.parse_args()


def log(*a):
    if not args.json:
        print(*a)


dev = frida.get_local_device()
if args.spawn:
    pid = dev.spawn([args.spawn])
    resume = True
    log("[*] spawned pid %d" % pid)
elif args.pid:
    pid = args.pid
    resume = False
    log("[*] attaching to pid %d" % pid)
else:
    pid = next((p.pid for p in dev.enumerate_processes() if p.name == args.name), None)
    if pid is None:
        sys.exit("[!] process '%s' not found — launch the (patched) app or pass --pid/--spawn." % args.name)
    resume = False
    log("[*] attaching to pid %d (%s)" % (pid, args.name))

session = dev.attach(pid)

captured_traffic = []

def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload", {})
        if payload.get("type") == "traffic":
            captured_traffic.append(payload.get("data", ""))

JS = r"""
const captured = [];

rpc.exports = {
  setupHook: function () {
    try {
      const mod = Process.findModuleByName("Sonos");
      if (mod) {
        // mbedtls_ssl_write offset from reverse-engineering notes: 0xc0a740
        const pWrite = mod.base.add(0xc0a740);
        Interceptor.attach(pWrite, {
          onEnter: function (args) {
            try {
              const len = args[2].toInt();
              if (len > 0 && len < 65536) {
                const s = args[1].readUtf8String(Math.min(len, 4096));
                if (s && (s.indexOf("googleapis.com") !== -1 || s.indexOf("refreshAuthToken") !== -1 ||
                          s.indexOf("loginToken") !== -1 || s.indexOf("X-Goog-Api-Key") !== -1)) {
                  send({ type: "traffic", data: s });
                }
              }
            } catch (e) {}
          }
        });
        return true;
      }
    } catch (e) {}
    return false;
  },

  scan: function () {
    const out = {
      header: [],
      heap: [],
      token: [],
      keys: [],
      households: []
    };
    const seenH = {}, seenK = {}, seenT = {}, seenKey = {}, seenHH = {};

    const HDR   = "58 2d 47 6f 6f 67 2d 41 70 69 2d 4b 65 79 3a 20"; // "X-Goog-Api-Key: "
    const AIZA  = "41 49 7a 61 53 79";                               // "AIzaSy"
    const BEAR  = "41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 65 61 72 65 72 20 79 61 32 39"; // "Authorization: Bearer ya29"
    const YA29  = "79 61 32 39 2e";                                  // "ya29."
    const KEY_T = "3c 6b 65 79 3e";                                  // "<key>"
    const PKEY  = "3c 70 72 69 76 61 74 65 4b 65 79 3e";             // "<privateKey>"
    const HH    = "53 6f 6e 6f 73 5f";                               // "Sonos_"

    for (const r of Process.enumerateRanges('rw-')) {
      // 1) X-Goog-Api-Key Header
      try {
        for (const m of Memory.scanSync(r.base, r.size, HDR)) {
          let s = ""; try { s = m.address.add(16).readUtf8String(45); } catch (e) { continue; }
          const x = /AIza[0-9A-Za-z_\-]{35}/.exec(s);
          if (x && !seenH[x[0]]) { seenH[x[0]] = 1; out.header.push(x[0]); }
        }
      } catch (e) {}

      // 2) AIza general heap
      try {
        for (const m of Memory.scanSync(r.base, r.size, AIZA)) {
          let s = ""; try { s = m.address.readUtf8String(45); } catch (e) { continue; }
          const x = /AIza[0-9A-Za-z_\-]{35}/.exec(s);
          if (x && !seenK[x[0]]) { seenK[x[0]] = 1; out.heap.push(x[0]); }
        }
      } catch (e) {}

      // 3) ya29 OAuth token
      const probeToken = function (addr, off) {
        let s = ""; try { s = addr.add(off).readUtf8String(400); } catch (e) { return; }
        const x = /ya29\.[0-9A-Za-z_\-]{20,}/.exec(s);
        if (x && !seenT[x[0]]) { seenT[x[0]] = 1; out.token.push(x[0]); }
      };
      try { for (const m of Memory.scanSync(r.base, r.size, BEAR)) probeToken(m.address, 22); } catch (e) {}
      try { for (const m of Memory.scanSync(r.base, r.size, YA29)) probeToken(m.address, 0); } catch (e) {}

      // 4) <key> or <privateKey> XML tags
      const probeKey = function (addr, tagLen) {
        let s = ""; try { s = addr.add(tagLen).readUtf8String(300); } catch (e) { return; }
        const x = /^([A-Za-z0-9+/=]{60,250})</.exec(s);
        if (x && !seenKey[x[1]]) { seenKey[x[1]] = 1; out.keys.push(x[1]); }
      };
      try { for (const m of Memory.scanSync(r.base, r.size, KEY_T)) probeKey(m.address, 5); } catch (e) {}
      try { for (const m of Memory.scanSync(r.base, r.size, PKEY)) probeKey(m.address, 12); } catch (e) {}

      // 5) householdId
      try {
        for (const m of Memory.scanSync(r.base, r.size, HH)) {
          let s = ""; try { s = m.address.readUtf8String(80); } catch (e) { continue; }
          const x = /Sonos_[0-9A-Za-z]{24,32}(?:_[0-9a-f]{6,10})?/.exec(s);
          if (x && !seenHH[x[0]]) { seenHH[x[0]] = 1; out.households.push(x[0]); }
        }
      } catch (e) {}
    }
    return out;
  }
};
"""

script = session.create_script(JS)
script.on("message", on_message)
script.load()

hooked = script.exports_sync.setup_hook()
if hooked:
    log("[✓] TLS hook active on mbedtls_ssl_write (intercepting live requests)")

if resume:
    dev.resume(pid)
    log("[*] let the app finish launching and open YouTube Music, then press Enter...")
    try: input()
    except EOFError: pass
elif args.listen > 0:
    log(f"[*] scanning memory & listening for {args.listen}s (click YouTube Music in the app to trigger traffic)...")
    time.sleep(args.listen)

res = script.exports_sync.scan()

# Process any captured TLS traffic from the hook
for traffic in captured_traffic:
    m_key = re.search(r"<(?:key|privateKey)>([A-Za-z0-9+/=]{60,250})</", traffic)
    if m_key and m_key.group(1) not in res["keys"]:
        res["keys"].append(m_key.group(1))

    m_tok = re.search(r"<authToken>(ya29\.[^<]+)</authToken>|Bearer (ya29\.[A-Za-z0-9_\-]+)", traffic)
    if m_tok:
        tok = m_tok.group(1) or m_tok.group(2)
        if tok not in res["token"]:
            res["token"].append(tok)

    m_hdr = re.search(r"X-Goog-Api-Key:\s*(AIza[0-9A-Za-z_\-]{35})", traffic)
    if m_hdr and m_hdr.group(1) not in res["header"]:
        res["header"].append(m_hdr.group(1))

    m_hh = re.search(r"<householdId>(Sonos_[^<]+)</householdId>", traffic)
    if m_hh and m_hh.group(1) not in res["households"]:
        res["households"].append(m_hh.group(1))

valid = lambda k: bool(re.fullmatch(r"AIza[0-9A-Za-z_\-]{35}", k))
api_key = res["header"][0] if res["header"] else (res["heap"][0] if res["heap"] else None)
ya29_token = res["token"][0] if res["token"] else None
private_key = res["keys"][0] if res["keys"] else None
household_id = res["households"][0] if res["households"] else None

# Get device info from speaker if possible
device_id = None
try:
    import soco
    sp = None
    if args.speaker:
        sp = soco.SoCo(args.speaker)
    else:
        discovered = list(soco.discover(timeout=2) or [])
        if discovered:
            sp = discovered[0]
    if sp:
        info = sp.get_speaker_info(timeout=2)
        if info.get("mac_address"):
            mac = info["mac_address"].replace(":", "-").upper()
            device_id = f"{mac}:B"
        if not household_id and sp.household_id:
            household_id = sp.household_id
except Exception:
    pass

household_id = household_id or "Sonos_Household"
device_id = device_id or "00-00-00-00-00-00:B"

if args.json:
    print(json.dumps({
        "x_goog_api_key": api_key,
        "x_sonos_api_key": "85f746ce-7307-4acf-bc36-71c9979d7b00",
        "private_key": private_key,
        "household_id": household_id,
        "device_id": device_id,
        "ya29": ya29_token,
        "api_key_candidates": sorted(set(res["header"] + res["heap"])),
    }, indent=2))
else:
    print("\n==================== RESULT ====================")
    if api_key:
        print(f"X-Goog-Api-Key: {api_key} ({'OK' if valid(api_key) else '?format'})")
    else:
        print("X-Goog-Api-Key: NOT FOUND (app hasn't made a Google request yet)")

    if private_key:
        print(f"private_key (<key>): {private_key[:20]}... ({len(private_key)} chars)")
    else:
        print("private_key (<key>): NOT FOUND in memory")

    if ya29_token:
        print(f"ya29 Bearer token: {ya29_token[:25]}... (live)")
    else:
        print("ya29 Bearer token: NOT FOUND")

    print(f"household_id: {household_id}")
    print(f"device_id:    {device_id}")
    print("===============================================")

if not args.no_save and api_key and (private_key or ya29_token):
    # Save sonos_creds.json
    creds_data = {
        "x_goog_api_key": api_key,
        "x_sonos_api_key": "85f746ce-7307-4acf-bc36-71c9979d7b00",
        "private_key": private_key or "",
        "household_id": household_id,
        "device_id": device_id
    }
    with open(DEFAULT_CFG, "w") as f:
        json.dump(creds_data, f, indent=2)
    log(f"[✓] Saved config to {DEFAULT_CFG}")

    if ya29_token:
        with open(DEFAULT_CACHE, "w") as f:
            json.dump({"token": ya29_token, "exp": time.time() + 50 * 60}, f)
        log(f"[✓] Cached live ya29 token to {DEFAULT_CACHE}")

try:
    session.detach()
except Exception:
    pass
