# Sonos S2 — как контроллер управляет YouTube Music (реверс-инжиниринг)

> Дата: 2026-11-25. Цель: понять, как десктоп-приложение Sonos (S2) браузит и
> проигрывает YouTube Music, чтобы повторить управление из Home Assistant.
> Все захваты делались с **собственной** колонкой и **собственным** аккаунтом
> для личной совместимости.

---

## 1. Окружение

- Машина: ThinkPad T480 (Hackintosh), macOS (Darwin 24.6).
- Приложение: `/Applications/Sonos.app` — легаси-десктоп S2 (`com.sonos.macController2`,
  build `90.0-82050`). Данные: `~/Library/Application Support/SonosV2/`.
- Колонка: **Sonos Move**, `<speaker-ip>`, `RINCON_<MAC>01400`, S2 18.3.
  - Household: `Sonos_<HOUSEHOLD>`
  - `zpSSLPort: 1443` (из `connectionsettings.txt`)
- YouTube Music = сервис Sonos SMAPI, **sid=284**, аккаунт-серийник **sn=3**.

---

## 2. Методология

### 2.1. Обход Hardened Runtime
Оригинальный бинарник подписан с Hardened Runtime (`flags=runtime`, TeamID `2G4LW83Q3E`) —
Frida к нему не прицепиться. Решение: скопировать приложение в scratchpad и
переподписать **ad-hoc без** hardened runtime, добавив `get-task-allow`:

```bash
cp -R /Applications/Sonos.app ./SonosPatched.app
# entitlements: com.apple.security.get-task-allow = true
codesign --force --deep -s - --entitlements ent.plist SonosPatched.app
# flags становятся 0x2(adhoc), runtime снят → Frida цепляется
```
Оригинал `/Applications/Sonos.app` **не трогали**.

### 2.2. Frida-перехват
- `driver.py` — спавнит пропатченный бинарник под Frida, грузит `tap.js`,
  пишет length-prefixed бинарный лог кадров.
- Перехватывали TLS-`SSL_write`/`SSL_read` и обычные сокеты (`write/read/send/recv`
  + `$NOCANCEL`/`__*_nocancel` варианты — на macOS CFNetwork пишет именно в nocancel).
- `connect()`-хук (в Frida 17 `Module.findExportByName` убрали — резолвили перебором
  экспортов модулей) — показал ВСЕ адреса/порты назначения в реальном времени.

### 2.3. Ключевой затык — четыре TLS-стека
Приложение несёт сразу несколько TLS-реализаций:
| Стек | Что обслуживает |
|---|---|
| системный **boringssl** (CFNetwork) | обложки `yt3.googleusercontent.com`, телеметрия Sentry |
| системный **SecureTransport** (`Security`) | вспомогательное |
| бандловый **OpenSSL** (`libssl.48`/`libcrypto.46` через `libcurl.4`) | вспомогательное |
| **вшитый mbedTLS** (статически в главном бинарнике) | **весь важный трафик: YT Music SMAPI + локальный API колонки** |

mbedTLS был вычислен по символам RTTI (`mbedtls_x509_crt`) в бинаре. Функции
вырезаны в локальные → по имени не найти.

### 2.4. Поиск `mbedtls_ssl_write` без символов
1. Хук на `write()`; когда шифртекст уходит в сокет на `:1443`/Google, снимали
   `Thread.backtrace(Backtracer.ACCURATE)`.
2. По первым байтам TLS-записи отличали handshake (`0x16`) от application data (`0x17`).
3. В стеке app-data return-адрес `MAIN+0xc0a833` оказался внутри `mbedtls_ssl_write`.
4. Скан пролога назад (`55 48 89 e5` = `push rbp; mov rbp,rsp`) → точка входа
   **`MAIN+0xc0a740`** (`base` в том запуске `0x10ed48000`).
5. `mbedtls_ssl_read` найден аналогично (`≈ MAIN+0xc0c2e0`).
6. Хук на вход `mbedtls_ssl_write(ctx, buf, len)` → `buf` = **открытый текст**.

Скрипты: `mbed_discover.py` (бэктрейсы), `mbed_capture.py` (полный дамп плейнтекста
в `muse_plain.bin`), `tap.js`/`driver.py`/`h2parse.py` (ранние этапы).

---

## 3. Архитектура: четыре сетевых канала

| Канал | Шифрование | Назначение |
|---|---|---|
| `<speaker-ip>:1400` | нет (HTTP/UPnP) | SSDP-дискавери, опрос `GetPositionInfo`, локальный `Browse` (`Q:0`, `FV:2`), `AVTransport` (воспроизведение/транспорт) |
| `<speaker-ip>:1443` | mbedTLS | локальный REST API колонки `/api/v1/...` (статус/батарея/настройки) |
| `music.googleapis.com:443` | mbedTLS | **браузинг и поиск YouTube Music (SMAPI)** |
| Google `:443` | boringssl | обложки альбомов + Sentry |

**QUIC/HTTP3 не используется** (проверено хуком `connect()` — ни одного UDP:443).

---

## 4. Протокол браузинга YouTube Music (расшифровано)

Приложение обращается к Google **напрямую**:

```
POST https://music.googleapis.com/v1:sendRequest  HTTP/1.1
HOST: music.googleapis.com
X-Goog-Api-Key: AIza…<REDACTED>           # Google-API-ключ приложения Sonos
AUTHORIZATION: Bearer ya29.<REDACTED>     # OAuth access-token аккаунта YT Music (~1 ч)
X-Sonos-Api-Key: 85f746ce-7307-4acf-bc36-71c9979d7b00
X-Sonos-Controller-ID: XX:XX:XX:XX:XX:XX
ACCEPT-ENCODING: gzip
CONTENT-TYPE: text/xml; charset="utf-8"
SOAPACTION: "http://www.sonos.com/Services/1.1#getMetadata"
```

Тело — Sonos SMAPI (SOAP 1.1):

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

### Пойманные операции SMAPI
- `getMetadata` — листание узлов. `<id>` = `root`, `ARTISTS`, либо id узла вида
  `ALkSOi...` (base64-подобные идентификаторы каталога YT Music).
- `getExtendedMetadata` — детальная карточка элемента.
- `search` — поиск:
  ```xml
  <search xmlns="http://www.sonos.com/Services/1.1">
    <id>ARTISTS</id><term>mogwai</term><index>0</index><count>100</count>
  </search>
  ```
- `getLastUpdate` — проверка версии каталога/избранного.

> Ответы (`mbedtls_ssl_read`) в этой сессии дампнуть не успели (эвристика read-хука
> подцепила не ту функцию); запросы захвачены полностью. Формат ответа — SMAPI
> `getMetadataResult` с `mediaCollection`/`mediaMetadata`, обложки указывают на
> `yt3.googleusercontent.com`.

### 4.1. Навигация по артисту и кривые фолты (находки клиентского слоя)

Две неочевидные вещи, всплывшие при реализации собственного клиента (`soco_ytmusic.py`):

**(A) Сервер иногда отдаёт невалидный XML в фолте.** На ошибочный запрос приходит
SOAP-`<fault>`, но внутри `<faultstring>` — сырой Java/RPC-дамп с **неэкранированными**
`<...>`, например `ImmutableList<...entitybrowser.v1.Entity>` и `cloud_project_number:<…>`.
Строгий парсер (`XML.fromstring` в soco) давится на этом (`mismatched tag`) и soco
переобзывает падение в «пустой ответ → не аутентифицирован». Официальное приложение
этим не страдает: оно (1) не провоцирует ошибку, т.к. ходит по валидным id, и
(2) читает **структурный код** `Code: INVALID_ARGUMENT` / `AppErrorCode=3`, а не текст.
Лечение на нашей стороне: faultstring разбирать **регексом + `html.unescape`**, а не XML;
развести настоящий auth (`TokenRefreshRequired`/`AuthTokenExpired`/`res:1035…`) от
прикладной ошибки (`Malformed resource name`, `INVALID_ARGUMENT`) и на последней **не**
гонять бесполезный рефреш токена.

**(B) id артиста из поиска — НЕ браузибельный.** `search("ARTISTS")` отдаёт id длиной
~69 символов; `getMetadata`/`getExtendedMetadata` по нему → `INVALID_ARGUMENT, Malformed
resource name`. Канонический **браузибельный** `artistId` (~48 символов) лежит **внутри
трека**:
```
getExtendedMetadata(trackId) → <trackMetadata><artistId>ALkSOi…(48)</artistId>
                                              <albumId>ALkSOi…(48)</albumId>
```
`getMetadata(canonical artistId)` возвращает **страницу артиста**: плейлисты
`Artist Shuffle` / `Artist Radio` / `Top Songs` + альбомы. Но трек-id внутри `Top Songs` —
**длинные (~106, playlist-контекст)** и напрямую не играются; их резолвят обратно в
короткий играбельный id: `getExtendedMetadata(longId) → <mediaMetadata><id>` = короткий
~48 (форма из §6). Короткий id альбомного трека играется напрямую, длинный из
плейлиста/поиска — нет.

---

## 5. Локальный REST API колонки (:1443)

Тоже поверх mbedTLS, но это **не** каталог:
```
GET /api/v1/players/RINCON_<MAC>01400/hardwareStatus/battery
GET /api/v1/users/<userId>/settings
```

---

## 6. Воспроизведение (локальный UPnP :1400, открытый текст)

Трек YT Music ставится в очередь/играется через `AVTransport` на колонке. Всё,
что нужно (аккаунт уже привязан на колонке, `sn=3`):

```
URI:       x-sonosapi-hls-static:<trackId>?sid=284&flags=8&sn=3
DIDL item: id="00032020<trackId>" parentID="00020000" restricted="true"
class:     object.item.audioItem.musicTrack
DESC:      <desc id="cdudn" nameSpace="urn:schemas-rinconnetworks-com:metadata-1-0/">
             SA_RINCON72711_X_#Svc72711-<hhsfx>-Token</desc>
res protocolInfo: sonos.com-http:*:application/x-mpegURL:*
```
Ставится через `AVTransport#AddURIToQueue` (это же делают soco / Music Assistant).

> ⚠️ Критично: `<trackId>` — это **короткий ~48-символьный** `<id>` из `getMetadata` **альбома**.
> Длинные ~100-символьные id из плейлистов/поиска в URI **не** годятся напрямую.

**✅ ВОСПРОИЗВЕДЕНИЕ ПРОВЕРЕНО ВЖИВУЮ (2026-11-25)** — `play_album.py` (soco 0.32.4):
проигран весь альбом **Lust For Life** (Iggy Pop, 9 треков) на громкости 3% —
`state: PLAYING`, позиция тикает. Рецепт (подтверждён с первой попытки):
```python
URI  = f"x-sonosapi-hls-static:{tid}?sid=284&flags=8&sn=3"
meta = DIDL(item id=f"00032020{tid}" parentID="00020000" class=musicTrack + cdudn-desc)
dev.avTransport.AddURIToQueue([('InstanceID',0),('EnqueuedURI',URI),
    ('EnqueuedURIMetaData',meta),('DesiredFirstTrackNumberEnqueued',0),('EnqueueAsNext',0)])
dev.play_from_queue(0)      # → NumTracksAdded/NewQueueLength, затем играет
```
`getMediaURI` вызывать НЕ нужно — статический URI + `cdudn` резолвятся на колонке при старте.

### 6.1. Бесконечное радио / станции (track radio, Artist Radio)

YT Music отдаёт и **бесконечные станции** — «радио от трека» и «радио артиста».
Играются они иначе, чем обычный трек.

**Где взять seed станции:**
- Радио от трека: `getExtendedMetadata(<trackId>)` → узел `<relatedPlay>` с
  `<itemType>program</itemType>` и длинным (~72 симв.) `programId`.
- Радио/шаффл артиста: на странице артиста узлы «Artist Radio» / «Artist Shuffle»
  (`itemType=playlist`, `canEnumerate=false`, `canPlay=true` — список бесконечен, можно только играть).

**Важно:** станция **НЕ** резолвится через `getMediaURI`/`getMediaMetadata`
(сервер отвечает «entity name not supported for playback» / считает её `PLAYLIST`).
Поток тянет сама колонка по URI-схеме радио.

**✅ Рабочий рецепт (подтверждён с первой попытки, `try_radio.py`):**
```
URI:    x-sonosapi-radio:<programId>?sid=284&flags=8300&sn=3
DIDL:   <item id="100c206c<programId>" parentID="-1" restricted="true">
          <upnp:class>object.item.audioItem.audioBroadcast.#station</upnp:class>
          <desc id="cdudn" …>SA_RINCON72711_X_#Svc72711-<hhsfx>-Token</desc>
        </item>
метод:  AVTransport#SetAVTransportURI  (НЕ AddURIToQueue!) → Play
```
После этого колонка сама докачивает конкретные `x-sonosapi-hls-static:` треки.
Проверено: радио от Teardrop → `PLAYING`, Massive Attack + похожее.

Отличие от одиночного трека: трек = `x-sonosapi-hls-static:…flags=8` + `AddURIToQueue`;
станция = `x-sonosapi-radio:…flags=8300` + `SetAVTransportURI`.

---

## 7. Выводы для Home Assistant

1. **Почему `soco` получал 403:** его AppLink бил в SMAPI-эндпоинт **без**
   `X-Goog-Api-Key` и без правильного flow. Теперь ключ и протокол известны.
2. **Браузинг/поиск напрямую:** можно повторить POST на
   `https://music.googleapis.com/v1:sendRequest` с `X-Goog-Api-Key` + валидным
   `Bearer` + SMAPI-телом (`getMetadata`/`search`).
3. **Обновление токена — решено (§10):** `Bearer ya29…` живёт ~1 час, но добывается
   автоматически вызовом SMAPI `refreshAuthToken` из долгоживущего `<key>`. Приложение
   для этого не нужно — PoC делает это сам.
4. **Воспроизведение — проверено (§6):** `AddURIToQueue` на :1400 с коротким track-id
   реально играет (весь цикл подтверждён вживую).
5. **Итог:** все три звена (браузинг/поиск + рефреш + воспроизведение) воспроизведены
   своим кодом без приложения. Для HA осталась только упаковка. Альтернатива для браузинга —
   **Music Assistant** (провайдер YT Music + плеер Sonos).

---

## 8. Безопасность

- В перехвате — **живой OAuth-токен и API-ключи**. В этом файле они **замаскированы**.
  Сырой дамп `muse_plain.bin` лежал только в эфемерном scratchpad сессии.
- `Bearer ya29…` протухает через ~1 час сам по себе.
- Оригинальное `/Applications/Sonos.app` не изменялось; патченая копия — только в scratchpad.
- Публиковать/пересылать сырой дамп или ключи — нельзя.

---

## 9. Идентификаторы (референс)

| Поле | Значение |
|---|---|
| Household | `Sonos_<HOUSEHOLD>` |
| Player (RINCON) | `RINCON_<MAC>01400` |
| SMAPI service id | `284` (YouTube Music), серийник `sn=3` |
| loginToken householdId | `Sonos_<HOUSEHOLD>_<hhsfx>` |
| cdudn token | `SA_RINCON72711_X_#Svc72711-<hhsfx>-Token` |
| X-Sonos-Api-Key | `85f746ce-7307-4acf-bc36-71c9979d7b00` |
| mbedtls_ssl_write | `MAIN+0xc0a740` (base `0x10ed48000` в том запуске) |
| mbedtls_ssl_read | `≈ MAIN+0xc0c2e0` |

---

## 10. Откуда берутся токены (происхождение)

Три токена разной природы:

**`X-Goog-Api-Key: AIza…` — общий ключ интеграции Sonos↔YouTube Music.**
- Плейнтекстом в приложении/бандле **нет**.
- Приезжает **зашифрованным** в манифесте сервиса (`284-manifest`, поле `apiKey.cr`/`apiKey.zp`;
  `cr` — для контроллера, `zp` — для колонки). Манифест тянется с `cf.ws.sonos.com`.
- Приложение расшифровывает `cr` в рантайме. Схему расшифровки мы НЕ ломали — и не нужно:
  готовый ключ поймали хуком `mbedtls_ssl_write`.
- Меняется крайне редко (смена сломала бы все старые приложения) → самая стабильная часть.

**`X-Sonos-Api-Key: 85f746ce-7307-4acf-bc36-71c9979d7b00` — статический ключ приложения** (константа).

**`Bearer ya29…` — OAuth access-token, куётся из refresh_token. ✅ МЕХАНИЗМ ПОЙМАН ВЖИВУЮ (2026-11-25).**

Ключевое открытие: рефреш — это **НЕ** прямой вызов Google OAuth2 (`oauth2.googleapis.com/token`).
Это обычный **SMAPI-экшн на том же эндпоинте**, что и браузинг:
```
POST https://music.googleapis.com/v1:sendRequest
SOAPACTION: "http://www.sonos.com/Services/1.1#refreshAuthToken"
Заголовки: X-Goog-Api-Key + X-Sonos-Api-Key   ← без второго сервер отвечает res:1037 (fail)
Тело (SOAP, credentials/loginToken):
    <token> = старый (протухший) ya29
    <key>   = base64(protobuf) — ДОЛГОЖИВУЩИЙ секрет (см. ниже)
Ответ: <refreshAuthTokenResult>
         <authToken>ya29…</authToken>     ← свежий Bearer (~1 час)
         <privateKey>…</privateKey>       ← тот же <key> (на случай ротации)
```

**Структура `<key>`/`<privateKey>`** — это protobuf, внутри лежит Google refresh_token:
```
field 1 (bytes, 103 B): "1//0…"        ← Google refresh token (долгоживущий)
field 2 (varint):       <timestamp мс> ← момент привязки аккаунта
```
То есть весь цикл обновления **замкнут внутри SMAPI** — приложение не ходит в Google OAuth напрямую,
а отдаёт refresh-блоб прокси Google (`music.googleapis.com`), который и возвращает свежий ya29.

Полная цепочка:
```
RSonosGetDeviceAuthTokenOp   разовая привязка аккаунта (AppLink): логин в Google →
                             Sonos получает долгоживущий refresh_token (внутри <key>-блоба)
      ↓ (хранится в household — на колонке; на Mac его можно достать из рефреш-запроса)
refreshAuthToken (SMAPI)      <key> + старый ya29 → свежий ya29 (~1 час)
      ↓
Bearer ya29…  → уходит в getMetadata/search на music.googleapis.com
```
Sonos-эндпоинты авторизации в бинаре (для первичной привязки): `sve.sslauth.sonos.com`,
`thor.ws.sonos.com/authz/v1/role/households/`.

«Хрупкость» по возрастанию: **API-ключ** (почти никогда) → **`<key>`/refresh_token** (при переприязке) →
**access-token ya29** (каждый час, добывается автоматически из `<key>`).

> ✅ Подтверждено: имея `<key>` + `X-Goog-Api-Key`, можно самостоятельно выписывать свежий ya29
> вызовом `refreshAuthToken` (HTTP 200). Приложение для этого больше не нужно — см. §11.

---

## 11. Proof-of-Concept: браузинг YouTube Music

Рабочий **самодостаточный** PoC (`ytmusic_standalone.py`): листает/ищет каталог YouTube Music
как приложение, и **сам выписывает свежий ya29** через `refreshAuthToken` — перехват/`muse_plain.bin`
больше НЕ нужен. Нужен только маленький конфиг `sonos_creds.json` с долгоживущими значениями:
```jsonc
{
  "x_goog_api_key":  "<ключ Google-интеграции Sonos, AIza…>",
  "x_sonos_api_key": "85f746ce-7307-4acf-bc36-71c9979d7b00",   // публичная константа
  "private_key":     "<base64 <key>-блоб: protobuf с refresh_token>",
  "household_id":    "Sonos_…",
  "device_id":       "XX-XX-XX-XX-XX-XX:B"
}
```
Свежий `ya29` кешируется в `.ya29_cache` с TTL ~55 мин и автоматически перевыпускается
при истечении или на 401. То есть PoC живёт сам по себе, без запущенного приложения Sonos.

### Результаты (живой каталог аккаунта, запуск БЕЗ капчи)
```
refresh:         fresh ya29 minted (261 chars), valid ~54 min   ← сам добыл токен
ROOT:            Home · Library · My Supermix
  → Library:     Playlists · Albums · Songs · Artists · Subscriptions · Podcasts
SEARCH "mogwai": Mogwai · Mogwai Beach Club · 808 MOGWAI · Iggy Pop
```
Все вызовы вернули HTTP 200 с реальными данными → протокол и рефреш воспроизведены полностью.
(Важно: id дочерних нод — полные ~60-символьные `ALkSOi…`; обрезанный id → `Malformed resource name`.)

### Код (`ytmusic_standalone.py`)
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

## 12. Статус и следующие шаги

**Исследование завершено (2026-11-25).**

Готово:
- ✅ Полная карта архитектуры (4 канала, mbedTLS).
- ✅ Расшифровка Muse/SMAPI-трафика (Frida + mbedTLS-хук).
- ✅ Протокол браузинга/поиска YouTube Music воспроизведён в PoC.
- ✅ **Механизм рефреша `ya29` пойман вживую** — это SMAPI `refreshAuthToken`, а не прямой
  Google OAuth2; `<key>` = protobuf с refresh_token (§10).
- ✅ **Самодостаточный PoC** (`ytmusic_standalone.py`): сам выписывает ya29 из `<key>`,
  кеширует, листает/ищет каталог — запущенное приложение больше не нужно (§11).
- ✅ Воспроизведение трека через локальный UPnP (поля в §6).

Теперь известно всё, что нужно для автономной интеграции в Home Assistant. Осталась
только инженерия (не реверс):
1. **Браузинг/поиск** — прямой SMAPI из `ytmusic_standalone.py` (готово).
2. ✅ **Воспроизведение** — `AddURIToQueue` на :1400 собрано и **проверено вживую** (§6,
   `play_album.py`): весь альбом Lust For Life отыгран на 3% громкости.
3. (опц.) **Расшифровать `apiKey.cr` из манифеста** — чтобы `x_goog_api_key` добывался сам,
   а не прописывался в конфиг (сейчас не блокер: ключ меняется крайне редко).
4. Упаковать в HA-интеграцию/`custom_component`. Практичная альтернатива для браузинга —
   Music Assistant (YT Music через `ytmusicapi`) + локальный UPnP для воспроизведения.

Долгоживущие креды (нужны PoC): `x_goog_api_key`, `private_key` (`<key>`-блоб), `household_id`,
`device_id`. `x_sonos_api_key` — публичная константа. Лежат в `sonos_creds.json` (scratchpad,
НЕ коммитить/не публиковать — содержит refresh-token).

Файлы сессии (эфемерный scratchpad, с живыми кредами — не хранить/не публиковать):
`SonosPatched.app`, `tap.js`, `driver.py`, `mbed_discover.py`, `mbed_capture.py`,
`refresh_capture.py`, `refresh_poc.py`, `muse_plain.bin`, `refresh_plain.bin`,
`sonos_creds.json`, `ytmusic_poc.py`, `ytmusic_standalone.py`, `h2parse.py`.
