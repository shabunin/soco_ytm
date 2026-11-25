# soco × YouTube Music — дизайн интеграции (разведка)

> Дата: 2026-11-25. Цель: понять, как добавить поддержку YouTube Music (SMAPI sid=284)
> в `soco`, что уже есть, чего не хватает, и каким минимальным кодом это закрыть.
> Это **разведка/дизайн** — кода пока не пишем. Основано на чтении исходников soco 0.32.4
> и на нашем реверсе (см. `reverse-engineering.ru.md`).

---

## 1. Итог одной строкой

soco уже реализует generic-SMAPI почти целиком (эндпоинт, credentials, token-store,
AppLink-авторизацию **и авто-рефреш токена**). Для YT Music не хватает буквально
двух HTTP-заголовков и, возможно, развязки «OAuth2-Bearer vs SMAPI-токен».
Хард-форк не нужен — хватит подкласса.

---

## 2. Что soco уже умеет (карта на наш реверс)

Модуль `soco/music_services/` (`music_service.py`, `accounts.py`, `token_store.py`):

| soco | наша находка (RE-док) |
|---|---|
| `MusicServiceSoapClient(endpoint=secure_uri, …)` | `secure_uri` из дескриптора = `music.googleapis.com/v1:sendRequest` ✅ |
| `get_soap_header()` → `<credentials><deviceId><deviceProvider>Sonos</deviceProvider><loginToken><token><key><householdId>` | **точь-в-точь** наша структура; `token`=ya29, `key`=refresh-блоб ✅ |
| `token_store` хранит пары `(token, key)` | наши `(ya29, <key>)` ✅ |
| `call()` ловит `SoapFault` `Client.TokenRefreshRequired`, достаёт из detail `RefreshAuthTokenResult/authToken+privateKey`, сохраняет пару и ретраит | **та же структура**, что вернул наш `refreshAuthToken` ✅ (!) |
| `begin_authentication`/`getAppLink`/`complete_authentication` | первичная привязка AppLink ✅ |
| `AddURIToQueue` / `SetAVTransportURI` (core.py) | воспроизведение — **уже работает**, проверено ✅ |

**Вывод:** протокол рефреша, который мы ловили как отдельный экшн `refreshAuthToken`,
у soco реализован как реакция на серверный фолт `Client.TokenRefreshRequired`. Сервер
YT Music, судя по совпадению структуры ответа, этот диалект поддерживает.

---

## 3. Ключевая развилка: две модели авторизации

Мы наблюдали у приложения **OAuth2-Bearer**-модель:
```
getMetadata:  HTTP-заголовок  Authorization: Bearer ya29…   +  loginToken{ТОЛЬКО householdId}
refresh:      отдельный SOAP-экшн refreshAuthToken, loginToken{token=старый ya29, key, householdId}
```
soco же реализует **классическую SMAPI**-модель:
```
любой вызов:  loginToken{token, key, householdId}  (токен ВНУТРИ тела, без Bearer)
refresh:      не отдельный экшн, а реакция на фолт Client.TokenRefreshRequired
```

Мы НЕ проверяли, принимает ли сервер YT Music классический путь (in-body token без Bearer).
**Это — главный эксперимент, определяющий объём кода (см. §5).**

- **Гипотеза A (оптимистичная):** сервер принимает in-body `loginToken{token,key}` и для
  протухшего токена отдаёт `Client.TokenRefreshRequired`. Тогда soco почти «из коробки»:
  достаточно добавить 2 заголовка — рефреш отработает сам.
- **Гипотеза B (что видели у приложения):** сервер требует `Authorization: Bearer`, in-body
  токен игнорит, протухание = HTTP 401 (не SMAPI-фолт). Тогда нужен подкласс: подставлять
  Bearer и проактивно рефрешить экшеном `refreshAuthToken`.

---

## 4. Чего не хватает soco для YT Music

1. **`X-Goog-Api-Key`** — soco шлёт только `Accept-Encoding` + `User-Agent`. Без ключа — отказ.
2. **`X-Sonos-Api-Key: 85f746ce-7307-4acf-bc36-71c9979d7b00`** — soco не шлёт; без него даже
   refresh даёт `res:1037`.
3. **(только для гипотезы B)** `Authorization: Bearer ya29` на HTTP-уровне + проактивный
   `refreshAuthToken`.
4. **Источник `X-Goog-Api-Key`** — в открытом виде нет; зашифрован в `284-manifest`
   (`apiKey.cr`), манифест тянется с `cf.ws.sonos.com`. soco знает `self.manifest_uri`, но
   схему расшифровки мы не ломали. На старте — подставляем пойманное значение из конфига.

---

## 5. Опорный эксперимент (делать первым)

Минимальной правкой проверить гипотезу A:
1. Положить в soco `token_store` нашу пару `(ya29, <key>)` для `service_id=284`.
2. Добавить в `http_headers` клиента `X-Goog-Api-Key` и `X-Sonos-Api-Key`.
3. Вызвать `MusicService('YouTube Music').get_metadata('root')`.

Исходы:
- **200 + каталог** → гипотеза A, интеграция почти тривиальна (soco сам рефрешит по фолту).
- **401 / "AuthTokenExpired"** с ПРОТУХШИМ ya29, но **фолт `TokenRefreshRequired`** → тоже A:
  soco сам обновит и повторит.
- **401 без SMAPI-фолта** (чистый HTTP) → гипотеза B, нужен подкласс с Bearer + проактивным
  рефрешем (наш `ytmusic_standalone.py`, перенесённый в класс).

---

## 6. Предлагаемый дизайн (подкласс, без форка)

Точки расширения (всё переопределяемо):
- `MusicService.__init__` создаёт `self.soap_client = MusicServiceSoapClient(...)`
  (music_service.py ~473) → подклассим `MusicService`, после `super().__init__` подменяем
  `self.soap_client` на свой.
- `MusicServiceSoapClient.http_headers` (dict, читается в момент вызова в `call()`).
- `MusicServiceSoapClient.get_soap_header()` — форма credentials.
- `MusicServiceSoapClient.call()` — уже содержит авто-рефреш по фолту.

Эскиз (псевдокод, НЕ реализация):
```python
class YouTubeMusicSoapClient(MusicServiceSoapClient):
    SONOS_API_KEY = "85f746ce-7307-4acf-bc36-71c9979d7b00"
    def __init__(self, *a, api_key, **kw):
        super().__init__(*a, **kw)
        self.http_headers["X-Goog-Api-Key"]  = api_key          # gap #1
        self.http_headers["X-Sonos-Api-Key"] = self.SONOS_API_KEY  # gap #2

    # --- только если подтвердится гипотеза B ---
    def call(self, method, args=None):
        tok, key = self.token_store.load_token_pair(284, self._device.household_id)
        self.http_headers["Authorization"] = "Bearer " + tok    # gap #3: Bearer на HTTP
        try:
            return super().call(method, args)                   # soco сам ретраит по фолту
        except MusicServiceAuthException:                        # HTTP-401 путь
            self._refresh(); return super().call(method, args)

    def get_soap_header(self):
        # для Bearer-модели: loginToken{ТОЛЬКО householdId}; для refresh — token+key
        ...

    def _refresh(self):
        # SOAP-экшн refreshAuthToken с loginToken{token,key,householdId}, БЕЗ Bearer
        # ответ → authToken + privateKey → token_store.save_token_pair(...)
        ...

class YouTubeMusic(MusicService):
    def __init__(self, token_store, device, api_key):
        super().__init__("YouTube Music", token_store, device)
        self.soap_client = YouTubeMusicSoapClient(
            endpoint=self.secure_uri, timeout=9, music_service=self,
            token_store=token_store, device=device, api_key=api_key)
```

Браузинг/поиск после этого — родные `get_metadata` / `search` soco (возвращают
`ms_data_structures` с `mediaCollection`/`mediaMetadata`).

---

## 7. Воспроизведение (менять soco НЕ нужно)

Уже работает чистым soco + наши DIDL-рецепты (см. RE-док §6/§6.1):
- Трек: `x-sonosapi-hls-static:<shortId>?sid=284&flags=8&sn=3`, DIDL `item id="00032020<id>"`,
  `AddURIToQueue`.
- Станция/радио: `x-sonosapi-radio:<programId>?sid=284&flags=8300&sn=3`,
  DIDL `item id="100c206c<id>"` class `audioBroadcast.#station`, `SetAVTransportURI`.

Нюанс: у soco есть `MusicService.sonos_uri_from_id()` — надо проверить, строит ли он URI
с правильными `flags`/`sn` для YT Music, или проще собирать URI своим хелпером (как у нас).

---

## 8. Первичная привязка аккаунта

- Путь soco: `begin_authentication()` → `getAppLink` отдаёт `regUrl`+`linkCode` → пользователь
  логинится в Google → `complete_authentication()` сохраняет первую пару `(token, key)`.
- Быстрый bootstrap (для PoC): положить в `token_store` уже пойманную пару — привязка на
  колонке у нас есть.

---

## 9. Открытые вопросы / риски

1. **Гипотеза A vs B** — решается опорным экспериментом (§5). Определяет объём кода.
2. **Расшифровка `apiKey.cr`** из манифеста не реверсилась. Пока — значение из конфига;
   в идеале — разобрать схему (`cr` для контроллера), тогда ключ добывается сам.
3. **Ротация `X-Goog-Api-Key`** — редкая, но не исключена; хранить в конфиге, уметь обновить.
4. **`sonos_uri_from_id()`** soco может не давать нужные `flags` → свой билдер URI.
5. **Парсинг ответов станций** — `program`/`relatedPlay` могут не ложиться в стандартные
   `ms_data_structures`; нужен лёгкий адаптер.
6. **Лицензия/апстрим** — если целимся в PR в soco, учесть их code style + тесты.

---

## 10. Рекомендация и следующий шаг

**Путь:** подкласс (`soco_ytmusic.py`) поверх pip-soco, без форка. Хард-форк/PR —
только если захотим отдать в апстрим.

**Первый шаг, когда продолжим:** опорный эксперимент §5 (2 заголовка + наша пара токенов →
`get_metadata('root')`). Его исход — A или B — фиксирует финальный объём подкласса:
- A: ~20 строк (два заголовка + инъекция пары, рефреш у soco свой).
- B: ~80–100 строк (плюс Bearer-слой и проактивный `refreshAuthToken`).

Воспроизведение в обоих случаях уже готово (чистый soco + наши рецепты).

---

## 11. Реализовано (2026-11-25): `soco_ytmusic.py` + Part A/B

Подтвердилась **гипотеза B**: YT Music требует `Authorization: Bearer` на HTTP-уровне,
встроенный в soco рефреш-по-фолту `TokenRefreshRequired` НЕ срабатывает (сервер отдаёт
свой фолт/401, не SMAPI-`TokenRefreshRequired`), поэтому рефрешим сами. Класс —
`YouTubeMusic(MusicService)` + `YouTubeMusicSoapClient(MusicServiceSoapClient)`, без форка.

**Part A — толерантная обработка фолтов (~55 строк).** Сервер иногда шлёт SOAP-`<fault>`
с невалидным XML внутри `<faultstring>` (неэкранированные `<...>` из Java-дампа) →
строгий `XML.fromstring` в soco падает → soco врёт «not authenticated» → старый код уходил
в бесполезный рефреш-шторм (14 парсингов). Фикс: модульный spy сохраняет сырые байты
ответа в `_LAST_RAW` перед парсингом; `_classify_fault()` читает faultstring регексом +
`html.unescape`, делит на `AUTH` (`TokenRefreshRequired`/`AuthTokenExpired`/`res:1035…`)
и `APP` (`Malformed resource name`/`INVALID_ARGUMENT`); `call()` на `APP` бросает чистый
`YTMusicFault` без рефреша, на `AUTH` — один рефреш+ретрай. Итог: `browse(artist)` →
`YTMusicFault: INVALID_ARGUMENT — Malformed resource name [...]`, 1 парсинг, 0.8s.

**Part B — навигация по артисту.** id из `search("ARTISTS")` (~69) НЕ браузибельный.
Канонический `artistId` (~48) берём из трека: `getExtendedMetadata(trackId) →
trackMetadata/artistId`. `browse(artistId)` → страница артиста (`Top Songs`,
`Artist Radio`, альбомы). Трек-id в `Top Songs` длинные (~106) → резолвим в короткий
играбельный через `getExtendedMetadata(longId) → mediaMetadata/id`. Методы:
`resolve_artist(name)`, `artist_id_of_track`, `artist_node`, `artist_top_tracks`,
`resolve_track`.

**Проверено вживую:** search ARTISTS/ALBUMS, browse root/album/artist, track_radio,
play_tracks, play_station, две колонки (Move <speaker-ip> + Roam 2 <speaker-ip-2>).
Демо: `play_tracks(Roam2, artist_top_tracks(resolve_artist("Koala Voice")))` → 12 треков
PLAYING. **Открытые дыры закрыты обходами**; осталось: первичный AppLink-онбординг,
расшифровка `apiKey.cr`, упаковка в pip + HA.
