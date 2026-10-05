# Coruna Research

**English** | [繁體中文](README.zh-TW.md) | [한국어](README.ko.md)

> [!CAUTION]
> This document records the analysis of malicious samples captured from a
> real-world iOS exploitation campaign. It is published **strictly for
> research purposes** — for defenders and threat researchers. No
> decryption keys, passwords, or seeds are published (they are described
> structurally so analysts holding a sample can locate them offline); no
> malicious binaries, exploit code, or C2 implementations are included;
> all indicators of compromise are defanged or genericized; no victim
> data is reproduced. The material describes what the attackers built —
> it must not be used to attack anyone. Samples must be handled only in
> isolated analysis environments.

## What this is

Deep-dive research on **Coruna**, a commercial-grade iOS exploit toolkit
observed in a real-world watering-hole campaign. The kit chains WebKit
exploits into full device compromise on iOS 13–17, then deploys a
23-module spyware system — crypto wallets, SMS, WhatsApp, and the photo
library — with command-and-control traffic hidden behind a
domain-generation algorithm (DGA).

This research builds on the analysis of captured toolkit samples.
Beyond *"what was delivered?"*, this document answers the next
questions: where the implant connects (the reversed DGA), what the
traffic looks like (the C2 protocol and a 90-request forensic timeline),
and what the malware does on the device (the module system and its
app-triggered exfiltration).

## Capabilities

| Capability | Detail |
|------------|--------|
| Supported iOS versions | iOS 13.0–17.2.1, per-version exploit chains (WebKit memory corruption → PAC bypass → sandbox escape) |
| Wallet theft | 19 wallet apps — MetaMask, imToken, Trust Wallet, TronLink, BitKeep, TON Keeper, Uniswap, Phantom, MyTonWallet, Exodus, Ronin, Krystal, TonHub, Global Wallet, Coin98, Bitpie, Solflare, OKX (EVM / Solana / TON / Tron / Ronin) |
| Module system | 23 injection modules: 19 wallets + WhatsApp (`wap.js`) + SMS (`sms.js`) + SpringBoard core payload (`new.js`) + config receiver (`helion.js`) |
| Photo album theft | device photos packaged into encrypted `.dat` containers (7z-derived format) and exfiltrated in bulk |
| SMS / SIM harvesting | phone number, SIM presence/validity, carrier details |
| C2 | DGA-generated domains, encrypted POST traffic, app-triggered bulk uploads |

## The attack chain at a glance

```
Victim opens watering-hole page (fake registration site)
  └─ hidden iframe pulls obfuscated loader JS
      ├─ Stage 1 — WebKit / WASM memory corruption → read/write primitives
      ├─ Stage 2 — PAC bypass (A12+ devices)
      └─ Stage 3 — sandbox escape + in-memory Mach-O loader
          └─ bootstrap.dylib decrypts/downloads .min.js payloads
              └─ implant persists via powerd / SpringBoard injection
                  └─ DGA-domain C2 traffic
                      └─ 23 injection modules → wallet / SMS /
                         WhatsApp / photo-library theft
```

## Key findings (TL;DR)

1. **Four crypto layers, all static keys.** ChaCha20 (DJB variant) for
   payload files with a 30-key hierarchy, a custom `F00DBEEF` container
   format, 7z AES-256 for runtime modules, and AES-256-ECB for C2
   traffic. Every key is either embedded in the samples or derivable
   offline — nothing requires per-device secrets.
2. **The DGA is fully reproducible.** A non-standard MurmurHash2 variant
   seeds a BSD libc `random()` generator; each domain costs one hash,
   one delay burn, and 15 RNG draws. Domains predicted from a sample's
   embedded seed match captured traffic exactly.
3. **The C2 protocol is small and asymmetric.** A plaintext `/vhx`
   heartbeat, Base64-encoded AES-256-ECB POST bodies keyed by a
   timestamp-derived key, and tiny fixed-size acknowledgment tokens.
4. **Exfiltration is app-triggered.** In the captured session, launching
   a crypto-wallet app produced an immediate beacon burst and two large
   encrypted uploads (1.8 MB and 624 KB); the photo library rides the
   same bulk channel.
5. **23 injection modules, 19 of them wallet-targeted,** spanning five
   ecosystems, plus WhatsApp, SMS, the photo library, and a SpringBoard
   core payload — a rentable surveillance product, not state espionage.

---

## 1. The Encryption Stack

| Layer | Protects | Algorithm | Key material |
|-------|----------|-----------|--------------|
| A | payload files (`.min.js`) | ChaCha20 (DJB variant) | 30-key hierarchy, embedded in delivery page & samples |
| B | file container format | custom `F00DBEEF` format | — (structure only) |
| C | runtime modules (`.7z`) | 7z AES-256 | one fixed campaign-wide password |
| D | C2 traffic | AES-256-ECB | timestamp-derived from an embedded prefix |

The single most important defensive finding: **nothing requires
per-device or per-session secrets.** The stack provides transport
obfuscation, not real confidentiality against anyone holding a sample.

### 1.1 Layer A — ChaCha20, the DJB variant

The payload files are *not* standard IETF ChaCha20. The implementation
inside `bootstrap.dylib` (offset `0xad8c`) is the original DJB variant:

- 64-bit counter, 64-bit nonce (all-zero in practice)
- magic `0x0BEDF00D` at the start of every plaintext
- after an 8-byte header, a raw XZ/lzma stream

Using a standard library with a 96-bit nonce produces garbage — the
classic failure mode when reversing this kit.

**Key hierarchy (three tiers):**

```
Tier 1 — master key (1): obfuscated uint32 array in group.html,
          passed to platformModule.init(); decoded to a 16-char JS
          string, stored UTF-16LE → 32-byte key. Opens the manifest.
Tier 2 — per-OS payload keys (19): entries at offset 0x120 inside the
          decrypted manifest, 100 bytes each. One payload per iOS
          version/architecture pair.
Tier 3 — sub-manifest keys (10): type-0x07 entries (468 bytes) inside
          each payload container, offset 0x0108. Shared modules.
```

Manifest entry layout:

```
0x00–0x1F : 32-byte ChaCha20 key (per-file)
0x20–0x27 : file size (LE64)
0x28      : entry type (0x01 = file, 0x07 = sub-manifest)
0x29–0x3F : padding
```

**The off-by-one pitfall:** the reference implementation hashes
`size - 1` bytes when decrypting manifest key tables. Naive "clean"
reimplementations that hash the full table produce wrong keys on the
last entry — one byte that silently breaks the whole pipeline.

### 1.2 Layer B — the F00DBEEF container

```
0x00–0x03 : 0BEDF00D            magic
0x04–0x07 : 0000000A            version
0x08–0x0B : segment count (LE)
0x0C–0x0F : 00000001            header size
0x20–..   : segment table (16 bytes per entry)
```

Segment types observed: `0x01` code, `0x02` config, `0x03` strings,
`0x07` sub-manifest (key material), `0x09` resources.

### 1.3 Layer C — 7z module transport

After installation, the implant fetches additional modules from
`/details/<name>.js` endpoints as 7z archives encrypted with **one
fixed, campaign-wide password** embedded as a constant in the binaries —
not device- or session-derived, and reused across modules and campaign
snapshots. The value is not published here.

### 1.4 Layer D — AES-256-ECB C2 traffic

```
key       = SHA256(<16-char fixed prefix embedded in every sample> + x-ts)[:32]
plaintext = <x-ts timestamp string> + <JSON payload>
padding   : PKCS7
transport : Base64(ciphertext) in POST body, timestamp echoed in x-ts header
response  : Base64(16 random bytes) — a 24-char acknowledgment token
```

Because the timestamp travels in the clear (`x-ts` header), any observer
of a session — or holder of a sample — can derive every request key. ECB
on JSON also leaks block-level repetition patterns.

### 1.5 Assessment

- **Weak confidentiality, strong obfuscation** — defeats casual
  inspection and naive gateway scanning only.
- **ECB misuse** makes traffic fingerprintable.
- **The off-by-one quirk and the DJB nonce variant are reliable
  implementation fingerprints** for identifying Coruna-family tooling in
  other campaigns.

---

## 2. The DGA — Algorithm Reverse Engineering

Coruna's implant does not carry a hardcoded C2 list. It embeds a single
32-hex-character seed and generates domains on demand. Blocking a live
domain only removes one host; predicting the full sequence turns the DGA
into a defensive asset.

Each generated domain costs exactly:

```
1 × murmurhash2_coruna(campaign_id)   → RNG seed
1 × delay burn                        → 1 of 10 uint16 slots consumed
15 × random()                          → label characters
```

The result is a 15-character lowercase `[a-z0-9]` label under a cheap,
disposable TLD (`.icu` in the captured campaign).

### 2.1 A non-standard MurmurHash2

```python
MURMUR_M = 0x5BD1E995
MURMUR_INIT = 0x12345678          # not the standard 0 seed

def murmurhash2_coruna(data: bytes, h: int = MURMUR_INIT) -> int:
    h ^= len(data)                # init differs from reference MurmurHash2
    for i in range(0, len(data) - (len(data) & 3), 4):
        k = int.from_bytes(data[i:i+4], "little")
        k = (k * MURMUR_M) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * MURMUR_M) & 0xFFFFFFFF
        h = (h * MURMUR_M) & 0xFFFFFFFF
        h ^= k
    tail = data[len(data) & ~3:]
    if len(tail) >= 3: h ^= tail[2] << 16
    if len(tail) >= 2: h ^= tail[1] << 8
    if len(tail) >= 1:
        h ^= tail[0]
        h = (h * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 15
    return h
```

### 2.2 BSD libc random(), TYPE_3

The implant uses BSD libc `random()`, not a naive LCG:

```python
class BSDRandom:
    """BSD libc random(), TYPE_3 (31-word state)."""

    DEG_3, SEP_3 = 31, 3

    def __init__(self, seed: int):
        self.state = [0] * self.DEG_3
        self.state[0] = seed & 0xFFFFFFFF
        word = seed & 0xFFFFFFFF
        for i in range(1, self.DEG_3):
            # Schrage-safe LCG, used only for state initialization
            hi, lo = divmod(word, 127773)
            word = ((16807 * lo - 2836 * hi) & 0x7FFFFFFF) or 0x7FFFFFFF
            self.state[i] = word
        for _ in range(310):       # warm-up discard
            self.next()

    def next(self) -> int:
        i, j = 0, self.SEP_3
        word = 0
        while word & 0x80000000 == 0:
            i, j = 0, self.SEP_3
            word = (self.state[i] & 0x7FFFFFFF) + self.state[j]
            self.state[i] = word
            i = j if (i := (i + 1) % self.DEG_3) == 0 else i
            j = j + 1 if (j := (j + 1) % self.DEG_3) == 0 else j
        return (word >> 1) & 0x7FFFFFFF
```

Trivial to reimplement — but only if you *know* it is TYPE_3 with the
310-draw warm-up. Guessing "it's just `rand()`" produces domains that
never match.

### 2.3 Label generation

```python
LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

def generate_domain(rnd: BSDRandom, tld: str = "icu") -> str:
    label = "".join(LABEL_CHARS[rnd.next() % len(LABEL_CHARS)]
                    for _ in range(15))
    return f"{label}.{tld}"
```

The implant keeps 10 delay slots (uint16 values); each domain
generation consumes one slot — a self-limiting pacing mechanism.

### 2.4 Where it lives, and verification

The DGA implementation sits in the non-exported function region of the
Mach-O payload; the campaign seed is at a fixed offset per campaign
generation (two observed campaign snapshots used different seeds —
operators rotate seeds, not the algorithm). Seed values are withheld.

Validation: seeding the reimplementation with the seed extracted from
the captured campaign's Mach-O reproduced the exact domain sequence
observed in the captured traffic — the first generated domain matched
the primary C2 host, the second matched the module-download host. The
DGA is fully deterministic: a defender holding any Coruna sample can
enumerate the campaign's complete future domain list before the
attacker registers those domains.

### 2.5 Defensive playbook

1. Extract the seed from a captured sample (fixed offset per campaign
   generation).
2. Regenerate the sequence — cost per domain: one hash, one delay burn,
   15 RNG draws (microseconds).
3. Blocklist / sinkhole the entire list at the DNS layer, including
   not-yet-registered domains.
4. Alert on registration of cheap-TLD domains matching the 15-char
   random `[a-z0-9]` label pattern.

### Implementation fingerprints

- MurmurHash2 with `0x12345678` seed constant; `h ^= len(data)` init.
- BSD `random()` TYPE_3 with 310-draw warm-up.
- Delay-slot pacing tied to domain generation.
- 15-char `[a-z0-9]` labels under cheap TLDs.

---

## 3. The C2 Protocol

Nine endpoints, one plaintext heartbeat, encrypted POSTs everywhere
else — deliberately minimal, and easy to fingerprint on the wire.

| Endpoint | Method | Purpose | Body |
|----------|--------|---------|------|
| `/vhx` | GET | heartbeat | plaintext `OK` response |
| `/a` | POST | registration / check-in | encrypted |
| `/event` | POST | event reporting | encrypted |
| `/u` | POST | installed-app inventory | encrypted |
| `/nb` | POST | bulk upload (photos, large data) | encrypted |
| `/ub` | POST | single upload | encrypted |
| `/details/<module>` | GET | module download (7z archive) | — |
| `/api/ip-sync/sync` | POST | operator-side IP sync | encrypted |
| `/config` | POST | config push/pull (`config.json`) | encrypted |

```
client                                         server
  │                                              │
  │  POST /a  (or /event /u /nb /ub …)           │
  │  headers:  x-ts: <unix-seconds>              │
  │  body:     Base64( AES-256-ECB(              │
  │              key = SHA256(PREFIX + x-ts)[:32],│
  │              pt  = x-ts ‖ JSON,              │
  │              pad = PKCS7 ) )                 │
  │─────────────────────────────────────────────>│
  │  200 OK                                       │
  │  body: Base64( 16 random bytes )             │
  │<─────────────────────────────────────────────│
```

`PREFIX` is a fixed 16-character constant compiled into every sample of
a campaign; its value is withheld (holders of a sample can extract it
as a string constant adjacent to the key-derivation call).

**Why this is weak:**

- The timestamp rides in the clear, so any network observer can derive
  every request key — the scheme protects only against casual payload
  inspection.
- AES-256-**ECB** on JSON leaks block-level repetition.
- The 16-random-byte acknowledgment carries no information; it exists
  only to give responses a fixed, recognizable size (24 Base64 chars).
- Registration includes stable device identifiers — implant sessions
  are trackable across domain rotations.

**Heartbeat lifecycle:** the implant periodically issues `GET /vhx` to
the current DGA domain; a live server answers plaintext `OK`. On
failure the implant advances its DGA cursor (consuming a delay slot)
and retries at the next generated domain — the "dead man's switch" that
keeps it reachable across takedowns, and the beacon that makes it
visible to passive DNS monitoring.

**Module fetch:** plain `GET` requests returning 7z-encrypted archives.
Modules are fetched lazily — only after the corresponding victim app is
detected or opened — so module traffic in a capture is a direct map of
the victim's installed apps.

**Config channel:** `helion.js` manages a JSON blob of per-module
settings, scheduling parameters, and domain-cursor state, cached on
disk; changes take effect without redeployment.

**Detection signatures:**

- Periodic plaintext `GET /vhx` → `OK` exchanges.
- Pure high-entropy Base64 POST bodies with a numeric `x-ts` header.
- Fixed-size 24-character response bodies.
- `GET /details/<name>.js` requests returning 7z archives.
- Bursts of encrypted POSTs immediately following victim-app launches.

---

## 4. Traffic Forensics — the 90-Request Timeline

A full infection session — watering-hole page to steady-state C2 — was
captured for analysis (~90 requests). It shows the complete lifecycle
in miniature.

| Phase | Traffic | What it reveals |
|-------|---------|-----------------|
| 1. Delivery | watering-hole page + hidden iframe assets | the lure and the exploit loader |
| 2. Infrastructure | IP-echo lookup, OCSP/CRL checks, operator sync host | recon and side-channel bookkeeping |
| 3. Implant startup | first DGA-domain contact, registration, app inventory, module downloads | the implant coming alive |
| 4. Steady state | heartbeat loop + event reports, bursts after victim-app launches | scheduling and exfiltration |

**The side channel (phase 2):** before the implant establishes itself,
the exploit layer queries a public IP-echo service ("what is my IP"),
then POSTs to an operator-controlled `/api/ip-sync/sync` endpoint —
synchronizing the victim's address with operator-side records. An
IP-echo query from a page followed by this obscure POST is not normal
web behavior and is a reliable pre-implant early indicator.

**Implant startup (phase 3):** the first DGA-generated domain appears
as a `CONNECT` to a 15-character random-label domain on a cheap TLD
with a freshly issued certificate. Within moments: heartbeat,
registration, app inventory, and module downloads.

**App-triggered exfiltration (phase 4):** steady state is a quiet
heartbeat/event loop; **launching a victim app detonates the
exfiltration.** In the captured session, opening a crypto-wallet app
(imToken) produced an immediate burst of `/event` reports, a **1.8 MB**
encrypted POST to the bulk-upload endpoint (`/nb`), and a follow-up
**624 KB** POST. The payloads are AES-encrypted containers; their sizes
and timing (not content) are the forensic signal.

**Judging "unknown" hosts** — misattributing non-malicious hosts wastes
effort:

| Host class | Verdict | Reason |
|------------|---------|--------|
| OCSP/CRL endpoints of the issuing CA | legitimate | standard TLS validation for the fresh certs |
| Public IP-echo service | legitimate service, malicious use | recon side channel |
| Operator sync host | malicious | operator bookkeeping |
| 15-char random-label cheap-TLD domains | malicious | DGA output (verified, §2) |

**POST size profile:**

| Endpoint | Typical size | Notes |
|----------|--------------|-------|
| `/event` | 0.5–0.7 KB | high frequency |
| `/a` | ~1.3 KB | once, at registration |
| `/u` | ~1 KB | periodic refresh |
| `/nb` | **1.8 MB / 624 KB observed** | bulk exfiltration, app-triggered |
| `/ub` | small | auxiliary upload path |

**Forensic checklist:**

1. Baseline the quiet loop: periodic `GET /vhx → OK` with `x-ts`-headed
   POSTs is the resting heartbeat.
2. Correlate bursts with app launches — a 1.8 MB encrypted POST seconds
   after a wallet app opens is near-conclusive.
3. Check any 15-char random-label domain against the DGA (§2).
4. Watch the side channel: IP-echo lookup followed by
   `POST /api/ip-sync/sync` identifies the campaign pre-implant.
5. Don't chase the CA — OCSP/CRL traffic is certificate infrastructure
   doing its job.

---

## 5. Payload Modules — Capabilities & Detection

| Capability | Modules involved | Notes |
|------------|------------------|-------|
| Wallet theft | 19 wallet modules | seed phrases, private keys, app data |
| Photo album theft | core + bulk upload | encrypted `.dat` containers via `/nb` |
| SMS / SIM | `sms.js` | phone number, SIM presence/validity, carrier |
| WhatsApp | `wap.js` | chat database access |
| Persistence / core | `new.js` (CorePayload.dylib) | SpringBoard injection, scheduling, DGA loop |
| Config & downloads | `helion.js` | `config.json` receiver, module fetcher |

The implant fetches 7z-encrypted modules over C2 and injects them into
running processes; downloads are **lazy** — the implant inventories
installed apps first (`/u`) and fetches only matching modules.

### The 19 wallet targets

| Ecosystem | Wallets |
|-----------|---------|
| EVM / multi-chain | MetaMask, Trust Wallet, imToken, BitKeep, OKX, Global Wallet, Krystal, Coin98, Bitpie, Exodus |
| Solana | Phantom, Solflare |
| TON | TON Keeper, MyTonWallet, TonHub |
| Tron | TronLink |
| DEX / others | Uniswap, Ronin |

Each wallet module harvests the app's sandbox data — key stores, seed
phrase backups, preferences — and packages it for the bulk-upload
channel.

### Photo album exfiltration

- Photos are packaged into custom `.dat` containers built with a
  PLzma-style SDK — a 7z-derived format combining AES encryption with
  LZMA2 compression, with an ARM64 BCJ branch filter (7z coder `0x0a`)
  applied in observed batches.
- Observed batches package on the order of a hundred photos per
  container.
- Containers ride the bulk-upload endpoint (`/nb`), matching the large
  encrypted POSTs in the captured session (§4).

### Supported iOS versions

| iOS range | Exploit chain (observed stage names) |
|-----------|---------------------------------------|
| 13.0–14.x | buffout → breezy |
| 15.0–15.5 | jacurutu → VariantB |
| 15.6–16.1 | bluebird → seedbell |
| 16.2–16.5 | terrorbird → seedbell |
| 16.6–17.2 | cassowary → seedbell_pre → seedbell_17 |

Payload manifests carry per-version/architecture entries (19 pairs in
the captured campaign), so the kit delivers a build matched to the
victim's exact OS. The `0x04` manifest flag family marks version
coverage — comparing these flags across samples distinguishes campaign
generations quickly.

### Detection & threat hunting

- **Process injection**: dylibs loaded into SpringBoard or powerd from
  non-system paths.
- **File artifacts**: encrypted `.dat` containers and `.min.js` files in
  app-writable locations; 7z archives fetched as `.js` URLs.
- **Behavioral**: wallet app launch followed within seconds by large
  encrypted uploads to freshly registered domains.
- **YARA opportunities**: the F00DBEEF magic, the DJB ChaCha20 constant
  sequence, and the MurmurHash2 `0x12345678` seed constant are reliable
  binary signatures.

### Assessment

The module roster reads like a product catalog: 19 wallets across five
ecosystems, plus WhatsApp, SMS, and the photo library — coverage
serving financially motivated theft rather than state-level espionage.
Combined with the commercial-looking version matrix, the kit is best
understood as a **rentable surveillance product** whose operators rotate
seeds and domains while reusing the core platform.

---

## License

Content is licensed under [CC BY 4.0](LICENSE).
