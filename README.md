# Coruna Research

**English** | [繁體中文](README.zh-TW.md) | [한국어](README.ko.md)

> [!CAUTION]
> This document records the analysis of malicious samples captured from a
> real-world iOS exploitation campaign. It is published **strictly for
> research purposes** — for defenders and threat researchers. No
> decryption keys, passwords, or seeds are published, and the inner
> workings of the toolkit's crypto and domain-generation machinery are
> deliberately not documented at a reproducible level of detail; no
> malicious binaries, exploit code, or C2 implementations are included;
> all indicators of compromise are defanged or genericized; no victim
> data is reproduced. The material describes observed behavior — it must
> not be used to attack anyone. Samples must be handled only in isolated
> analysis environments.

## What this is

Deep-dive research on **Coruna**, a commercial-grade iOS exploit toolkit
observed in a real-world watering-hole campaign. The kit chains WebKit
exploits into full device compromise on iOS 13–17, then deploys a
23-module spyware system — crypto wallets, SMS, WhatsApp, and the photo
library — with command-and-control traffic hidden behind a
domain-generation algorithm (DGA).

This research builds on the analysis of captured toolkit samples.
Beyond *"what was delivered?"*, this document answers the next
questions: how the implant hides its infrastructure, what the traffic
looks like (the C2 protocol and a 90-request forensic timeline), and
what the malware does on the device (the module system and its
app-triggered exfiltration).

## Capabilities

| Capability | Detail |
|------------|--------|
| Supported iOS versions | iOS 13.0–17.2.1, per-version exploit chains (WebKit memory corruption → PAC bypass → sandbox escape) |
| Wallet theft | 19 wallet apps — MetaMask, imToken, Trust Wallet, TronLink, BitKeep, TON Keeper, Uniswap, Phantom, MyTonWallet, Exodus, Ronin, Krystal, TonHub, Global Wallet, Coin98, Bitpie, Solflare, OKX (EVM / Solana / TON / Tron / Ronin) |
| Module system | 23 injection modules: 19 wallets + WhatsApp (`wap.js`) + SMS (`sms.js`) + SpringBoard core payload (`new.js`) + config receiver (`helion.js`) |
| Photo album theft | device photos packaged into encrypted containers and exfiltrated in bulk |
| SMS / SIM harvesting | phone number, SIM presence/validity, carrier details |
| C2 | generated domains, encrypted POST traffic, app-triggered bulk uploads |

## The attack chain at a glance

```
Victim opens watering-hole page (fake registration site)
  └─ hidden iframe pulls obfuscated loader JS
      ├─ Stage 1 — WebKit / WASM memory corruption → read/write primitives
      ├─ Stage 2 — PAC bypass (A12+ devices)
      └─ Stage 3 — sandbox escape + in-memory Mach-O loader
          └─ bootstrap stage delivers the encrypted payload modules
              └─ implant persists via powerd / SpringBoard injection
                  └─ generated-domain C2 traffic
                      └─ 23 injection modules → wallet / SMS /
                         WhatsApp / photo-library theft
```

## Key findings (TL;DR)

1. **All-static crypto materials.** The toolkit wraps its payloads,
   modules, and traffic in multiple layers of encryption, but every key
   it uses is embedded in the samples themselves — nothing is device-
   or session-specific. The encryption is transport obfuscation, not
   real confidentiality against anyone holding a sample.
2. **DGA-hidden infrastructure.** C2 domains are generated on demand
   from material embedded in the implant: 15-character random
   alphanumeric labels under cheap TLDs. The sequence is fully
   deterministic, so defenders holding a sample can anticipate the
   campaign's future domains and pre-block them at the DNS layer.
3. **The C2 protocol is small and asymmetric.** A plaintext `/vhx`
   heartbeat, encrypted POST bodies, and tiny fixed-size acknowledgment
   tokens — low-profile by design.
4. **Exfiltration is app-triggered.** In the captured session, launching
   a crypto-wallet app produced an immediate beacon burst and two large
   encrypted uploads (1.8 MB and 624 KB); the photo library rides the
   same bulk channel.
5. **23 injection modules, 19 of them wallet-targeted,** spanning five
   ecosystems, plus WhatsApp, SMS, the photo library, and a SpringBoard
   core payload — a rentable surveillance product, not state espionage.

---

## 1. The C2 Protocol

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
| `/details/<module>` | GET | module download | archive-format payload |
| `/api/ip-sync/sync` | POST | operator-side IP sync | encrypted |
| `/config` | POST | config push/pull (`config.json`) | encrypted |

**Encrypted POST channel.** All reporting and upload endpoints carry
encrypted bodies; the key material is compiled into every sample of the
campaign. Responses are fixed-size tokens that carry no information —
they exist only to give replies a constant, recognizable shape. The
design goal is clearly low-profile traffic rather than cryptographic
strength: the scheme protects against casual inspection only, and the
wire shape (see detection signatures below) is itself the strongest
forensic signal.

**Heartbeat lifecycle.** The implant periodically issues `GET /vhx` to
the current generated domain; a live server answers plaintext `OK`. On
failure the implant advances to the next generated domain — the
"dead man's switch" that keeps it reachable across takedowns, and the
beacon that makes it visible to passive DNS monitoring.

**Module fetch.** Plain `GET` requests returning encrypted,
archive-format files. Modules are fetched lazily — only after the
corresponding victim app is detected or opened — so module traffic in
a capture is a direct map of the victim's installed apps.

**Config channel.** A dedicated module manages a JSON blob of
per-module settings, scheduling parameters, and domain-cursor state,
cached on disk; changes take effect without redeployment.

**Detection signatures.**

- Periodic plaintext `GET /vhx` → `OK` exchanges.
- High-entropy POST bodies to freshly registered cheap-TLD domains.
- Fixed-size, roughly 24-character response bodies.
- `.js`-named URLs returning archive-format binaries.
- Bursts of encrypted POSTs immediately following victim-app launches.

---

## 2. Traffic Forensics — the 90-Request Timeline

A full infection session — watering-hole page to steady-state C2 — was
captured for analysis (~90 requests). It shows the complete lifecycle
in miniature.

| Phase | Traffic | What it reveals |
|-------|---------|-----------------|
| 1. Delivery | watering-hole page + hidden iframe assets | the lure and the exploit loader |
| 2. Infrastructure | IP-echo lookup, OCSP/CRL checks, operator sync host | recon and side-channel bookkeeping |
| 3. Implant startup | first generated-domain contact, registration, app inventory, module downloads | the implant coming alive |
| 4. Steady state | heartbeat loop + event reports, bursts after victim-app launches | scheduling and exfiltration |

**The side channel (phase 2):** before the implant establishes itself,
the exploit layer queries a public IP-echo service ("what is my IP"),
then POSTs to an operator-controlled `/api/ip-sync/sync` endpoint —
synchronizing the victim's address with operator-side records. An
IP-echo query from a page followed by this obscure POST is not normal
web behavior and is a reliable pre-implant early indicator.

**Implant startup (phase 3):** the first generated domain appears as a
`CONNECT` to a 15-character random-label domain on a cheap TLD with a
freshly issued certificate. Within moments: heartbeat, registration,
app inventory, and module downloads.

**App-triggered exfiltration (phase 4):** steady state is a quiet
heartbeat/event loop; **launching a victim app detonates the
exfiltration.** In the captured session, opening a crypto-wallet app
(imToken) produced an immediate burst of `/event` reports, a **1.8 MB**
encrypted POST to the bulk-upload endpoint (`/nb`), and a follow-up
**624 KB** POST. The payloads are encrypted containers; their sizes and
timing (not content) are the forensic signal.

**Judging "unknown" hosts** — misattributing non-malicious hosts wastes
effort:

| Host class | Verdict | Reason |
|------------|---------|--------|
| OCSP/CRL endpoints of the issuing CA | legitimate | standard TLS validation for the fresh certs |
| Public IP-echo service | legitimate service, malicious use | recon side channel |
| Operator sync host | malicious | operator bookkeeping |
| 15-char random-label cheap-TLD domains | malicious | generated by the implant's domain algorithm |

**POST size profile:**

| Endpoint | Typical size | Notes |
|----------|--------------|-------|
| `/event` | 0.5–0.7 KB | high frequency |
| `/a` | ~1.3 KB | once, at registration |
| `/u` | ~1 KB | periodic refresh |
| `/nb` | **1.8 MB / 624 KB observed** | bulk exfiltration, app-triggered |
| `/ub` | small | auxiliary upload path |

**Forensic checklist:**

1. Baseline the quiet loop: periodic `GET /vhx → OK` with small
   encrypted POSTs is the resting heartbeat.
2. Correlate bursts with app launches — a 1.8 MB encrypted POST seconds
   after a wallet app opens is near-conclusive.
3. Watch domain shape: any 15-character random-label cheap-TLD domain
   contacted by the device matches the campaign's generated-domain
   pattern.
4. Watch the side channel: IP-echo lookup followed by
   `POST /api/ip-sync/sync` identifies the campaign pre-implant.
5. Don't chase the CA — OCSP/CRL traffic is certificate infrastructure
   doing its job.

---

## 3. Payload Modules — Capabilities & Detection

| Capability | Modules involved | Notes |
|------------|------------------|-------|
| Wallet theft | 19 wallet modules | seed phrases, private keys, app data |
| Photo album theft | core + bulk upload | encrypted containers via `/nb` |
| SMS / SIM | `sms.js` | phone number, SIM presence/validity, carrier |
| WhatsApp | `wap.js` | chat database access |
| Persistence / core | `new.js` (CorePayload.dylib) | SpringBoard injection, scheduling |
| Config & downloads | `helion.js` | `config.json` receiver, module fetcher |

The implant fetches encrypted modules over C2 and injects them into
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

- Photos are packaged into encrypted, compressed containers in a
  7z-derived format before transmission.
- Observed batches package on the order of a hundred photos per
  container.
- Containers ride the bulk-upload endpoint (`/nb`), matching the large
  encrypted POSTs in the captured session (§2).

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
victim's exact OS. Version-coverage flags inside the manifest
distinguish campaign generations quickly when comparing samples.

### Detection & threat hunting

- **Process injection**: dylibs loaded into SpringBoard or powerd from
  non-system paths.
- **File artifacts**: encrypted `.dat` containers and staged payload
  files in app-writable locations; `.js` URLs returning archive-format
  binaries.
- **Behavioral**: wallet app launch followed within seconds by large
  encrypted uploads to freshly registered domains.
- **YARA opportunities**: distinctive magic values and algorithm
  constants embedded in the captured binaries make reliable signature
  material for this family (specific values withheld from this
  publication).

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
