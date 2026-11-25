# soco_ytm — YouTube Music on Sonos from Python & CLI

Control and stream **YouTube Music** on your local **Sonos** speakers directly from Python and the command line, using Sonos SMAPI (`sid=284`).

---

## Features

- **Direct Playback**: Search songs, albums, and artists, enqueue and stream via local UPnP/AVTransport.
- **Endless Radio**: Launch track radio or artist radio stations (`x-sonosapi-radio`).
- **Artist Navigation**: Resolves canonical artist pages, discography, and Top Songs.
- **Auto-Refresh**: Self-contained hourly OAuth token refresh using SMAPI `refreshAuthToken` from the durable refresh token blob.
- **Tolerant Fault Handling**: Custom XML/regex parser that handles malformed Java stack traces in Google/Sonos SOAP faults without crash loops.
- **Interactive CLI**: Control volume, track info, pause, resume, skip, and speaker discovery.

---

## How It Works

Sonos integrates with YouTube Music via SMAPI (`https://music.googleapis.com/v1:sendRequest`) using an `Authorization: Bearer <ya29>` HTTP header and proprietary API keys. 

To use this library with your own Sonos system, you extract your system's Google API key and SMAPI credentials once from your local Sonos desktop app using the included helper tools.

For full reverse-engineering details, see [docs/reverse-engineering.md](docs/reverse-engineering.md) and [docs/integration-design.md](docs/integration-design.md) (in Russian; Russian original of the RE doc: [docs/reverse-engineering.ru.md](docs/reverse-engineering.ru.md)).

---

## Getting Started

### 1. Installation

Clone this repository and install dependencies:

```bash
git clone https://github.com/shabunin/soco_ytm.git
cd soco_ytm

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. One-Time Credential Setup

Because Sonos encrypts the Google API key in its bundle (`apiKey.cr`) and stores tokens in macOS Keychain, credentials are read from process memory:

1. **Quit the running Sonos app** (`Cmd + Q`).
2. **Create a debuggable copy** of `Sonos.app`:
   ```bash
   chmod +x patch_sonos.sh
   ./patch_sonos.sh
   ```
3. **Launch the patched app**:
   ```bash
   open ./SonosPatched.app
   ```
4. **Click YouTube Music** once in the app (browse or play any song).
5. **Run the extractor**:
   ```bash
   python3 extract_apikey.py
   ```

This generates `sonos_creds.json` and `.ya29_cache` in the project directory. You can now close `SonosPatched.app`.

---

## CLI Usage

### Playback

```bash
# Play a track
python3 soco_ytmusic.py play "Daft Punk - Get Lucky"

# Play an artist's top tracks
python3 soco_ytmusic.py artist "Massive Attack"

# Start an endless radio station
python3 soco_ytmusic.py station "Teardrop"
```

### Search & Browse

```bash
# Search songs
python3 soco_ytmusic.py search SONGS "Instant Crush"

# Search albums or artists
python3 soco_ytmusic.py search ALBUMS "Random Access Memories"
python3 soco_ytmusic.py search ARTISTS "Gorillaz"

# Browse library root
python3 soco_ytmusic.py browse root
```

### Speaker Control

```bash
# Discover speakers on your LAN
python3 soco_ytmusic.py speakers

# View currently playing track
python3 soco_ytmusic.py info

# Adjust volume (0 - 100)
python3 soco_ytmusic.py volume 20

# Transport controls
python3 soco_ytmusic.py pause
python3 soco_ytmusic.py resume
python3 soco_ytmusic.py next
python3 soco_ytmusic.py prev
python3 soco_ytmusic.py stop
```

### Target a Specific Speaker

Specify a speaker by IP or name with `--speaker`, or set the `SONOS_SPEAKER` environment variable:

```bash
python3 soco_ytmusic.py --speaker 192.168.1.50 play "Radiohead - Creep"
# or
export SONOS_SPEAKER="Living Room"
python3 soco_ytmusic.py play "Pink Floyd - Time"
```

---

## Python API

You can also use `soco_ytm` as a library in your own Python scripts:

```python
import soco
from soco_ytmusic import YouTubeMusic

speaker = soco.SoCo("192.168.1.50")
ym = YouTubeMusic(device=speaker)

# Search
results = ym.search("SONGS", "Paranoid Android")

# Play
track = ym.resolve_track(results[0]["id"])
ym.play_tracks(speaker, [track])

# Start radio station
program_id = ym.track_radio(results[0]["id"])
ym.play_station(speaker, program_id, title="Paranoid Android Radio")
```

---

## Security & Secrets

> ⚠️ **Important**: 
> - `sonos_creds.json` and `.ya29_cache` contain your personal account tokens and keys. **Never commit them to version control.**
> - They are excluded by default in `.gitignore`.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
