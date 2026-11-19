# Cloudflare Scanner Tool Landscape

Research on public open-source Cloudflare WARP endpoint scanners and CDN IP "optimization" tools, with emphasis on the Iranian, Russian, and Chinese communities where these tools are most developed. Everything here is from public repositories and public documentation; all techniques described are scans of Cloudflare's *own* published IP ranges and services (the same ranges Cloudflare [publishes itself](https://www.cloudflare.com/ips/) and documents for [reachability testing](https://www.cloudflarestatus.com/)).

Verification method: GitHub search + raw source fetches. Where a claim is verified directly in source code, the file is linked as `repo/file.go`. Where a claim comes only from a README or third-party summary (DeepWiki, search previews), it is flagged **[README-only]** or **[unverified]**.

> ### Corrections (2026-11-16)
>
> Three claims below were re-checked directly against primary source after the first draft and are **outdated**. `02-warp-scan.md` uses the corrected values.
>
> 1. §2.7 says "Current API version in wgcf master: `v0a884`". The current master constant is `ApiVersion = "v0a5641"` ([cloudflare/api.go:25](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go)). The build number 5641 appears in the URL version segment, the User-Agent and the CF-Client-Version header — all three derive from one build number.
> 2. The wgcf User-Agent is `1.1.1.1/6.38.9-5641 (Android 16.0.0)` with `CF-Client-Version: a-6.38.9-5641` ([api.go:31-32](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go)). The `okhttp/3.12.1` User-Agent quoted elsewhere in this file comes from a *different* client (badafans/warp-reg), not from wgcf.
> 3. The WARP peer public key is **not** a hardcoded constant in wgcf master: the profile generator reads `thisDevice.Config.Peers[0]` and uses the `public_key` and `endpoint` the API returned ([cmd/generate/generate.go:54](https://github.com/ViRb3/wgcf/blob/master/cmd/generate/generate.go), [openapi/model_peer.go](https://github.com/ViRb3/wgcf/blob/master/openapi/model_peer.go)). The widely quoted `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=` comes from older wgcf releases and third-party profiles — treat it as **unverified** unless checked against a live registration.
>
> Also verified: wgcf pins TLS 1.2 as both minimum and maximum and assembles the ClientHello with uTLS to match the Android app ([api.go:39-47,107-124](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go)).
>
> 4. The §2.2 heading "The canonical 55/56-port list" is stale: the list enumerated there contains exactly **54** entries (counted), and that is the number `02-warp-scan.md` §3 uses everywhere (the `full` mode multiplier, the packet charges and the floor arithmetic). Use 54.

---

## 1. Tool inventory

### WARP endpoint scanners

| Tool | Community | Repo | What it does | License |
|---|---|---|---|---|
| **warp-plus** (ipscanner pkg) | Iran (bepass-org) | [bepass-org/warp-plus](https://github.com/bepass-org/warp-plus) | Anti-censorship WARP client; built-in real WireGuard-handshake endpoint scanner feeding its own tunnel | MIT |
| **oblivion / oblivion-desktop** | Iran (bepass-org) | [bepass-org/oblivion](https://github.com/bepass-org/oblivion), [oblivion-desktop](https://github.com/bepass-org/oblivion-desktop) | GUI wrappers around warp-plus; endpoint field empty or `engage.cloudflareclient.com:2408` activates the internal scanner ([wiki](https://github.com/bepass-org/oblivion-desktop/wiki/Slow-Connection-with-the-Default-Endpoint)) | MIT **[README-only]** |
| **BPB-Warp-Scanner** | Iran (bia-pain-bache) | [bia-pain-bache/BPB-Warp-Scanner](https://github.com/bia-pain-bache/BPB-Warp-Scanner) | Cross-platform endpoint scanner using **Xray-core** as the probe engine; UDP-noise support matching BPB Panel's noise config | **[unverified]** |
| **warpscout** | Russia (vernette) | [vernette/warpscout](https://github.com/vernette/warpscout) | Single-binary Go scanner over wg / AmneziaWG / MASQUE; reports exit country + Cloudflare edge node (colo) per endpoint; DPI "torn down" detection; AmneziaWG junk-parameter search (`find-junk`), MASQUE SNI search (`find-sni`) | MIT |
| **awarp / warp-cli (Skiro1)** | Russia | [Skiro1/warp-cli](https://github.com/Skiro1/warp-cli) | AmneziaWG WARP tunnel CLI on Windows with a 2-phase scanner: ICMP ping pre-filter → full Noise-IKpsk2 handshake probe on 54 ports; community endpoint lists from ircfspace/endpoint | **[README-only]** |
| **warpfind** | Russia | [yaroslaff/warpfind](https://github.com/yaroslaff/warpfind) | Python tool that scans subnets × ports by bringing up real `wireproxy-awg` tunnels against each candidate | **[README-only]** |
| **CloudflareWarpSpeedTest** | China (puzige) | [puzige/CloudflareWarpSpeedTest](https://github.com/puzige/CloudflareWarpSpeedTest) | WARP-flavored fork of XIU2's tool: WireGuard handshake latency + port discovery + in-tunnel speed test; the alternate port sweep and RTT/loss measurement warpscout credits | GPL-3.0 |
| **Ptechgithub/warp** | Iran | [Ptechgithub/warp](https://github.com/Ptechgithub/warp) | Termux/Windows endpoint scanner + free WireGuard config generator; the "Peyman scanner" cited in warp-plus issues | **[README-only]** |
| **arshiacomplus/WarpScanner** | Iran | [arshiacomplus/warpscanner](https://github.com/arshiacomplus/warpscanner) | Android GUI (Kotlin) + Termux scanner, 5 languages, WireGuard config generation | GPL-3.0 **[README-only]** |
| **Warp-Endpoint-IP** | Iran-diaspora | [TheyCallMeSecond/WARP-Endpoint-IP](https://github.com/TheyCallMeSecond/WARP-Endpoint-IP) | Bash wrapper: generates random IPs from the classic /24 pools, feeds them to a compiled scanner binary, outputs result.csv | **[README-only]** |
| **Shellgate/warp-endpoint** | Iran-oriented | [Shellgate/warp-endpoint](https://github.com/Shellgate/warp-endpoint) | Parallel bash script, finds 4 lowest-ping endpoints across all IPv4 pools | **[README-only]** |
| **DarknessShade/Warp-Endpoint-Scanner** | automation | [DarknessShade/Warp-Endpoint-Scanner](https://github.com/DarknessShade/Warp-Endpoint-Scanner) | GitHub-Actions cron that scans daily and publishes results as a README table | **[README-only]** |
| **cf-knife** | Iran (Danialsamadi) | [Danialsamadi/cf-knife](https://github.com/Danialsamadi/cf-knife) | Multi-CDN scanner: TCP/TLS/HTTP/H2/H3 probes, domain-mode DPI-bypass scanning, WARP UDP mode (`--warp --warp-port 2408`), DNS-poison detection, TLS/MITM checks | **[README-only]** |
| **CF-IP-Scanner** | Iran (Khate-Tire) | [Khate-Tire/CF-IP-Scanner](https://github.com/Khate-Tire/CF-IP-Scanner) | GUI: Cloudflare + Fastly clean-IP scan, WARP scanner, DPI fragment analyzer, SNI fronting, speed tests | **[README-only]** |
| **UMBRA** | Iran (0xAKIRAVX) | [0xAKIRAVX/UMBRA](https://github.com/0xAKIRAVX/UMBRA) | Native Android: Rust WireGuard handshake core + Go clean-IP engine; ranks endpoints by in-tunnel ping/loss/speed; generates VLESS configs | **[README-only]** |
| **MiSaturo/WarpScanner** | China/Russia | [MiSaturo/WarpScanner](https://github.com/MiSaturo/WarpScanner) | Bash `endip.sh`: random IP generation from the 7 classic /24s feeding a downloaded scanner binary | **[README-only]** |
| **warp-yxip** | China | [siq0o/warp-yxip](https://github.com/siq0o/warp-yxip) | Shell endpoint scanner | **[README-only]** |

### CDN IP scanners / "IP optimization" (优选IP)

| Tool | Community | Repo | What it does | License |
|---|---|---|---|---|
| **CloudflareSpeedTest (CFST)** | China (XIU2) — the canonical tool | [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) (~30k stars) | TCPing/HTTPing latency filter → download speed test over Cloudflare published ranges; CSV output; the template nearly all CDN scanners copy | GPL-3.0 |
| **better-cloudflare-ip** | China (badafans) | [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip) (~3.5k stars) | Older Windows-first 优选 tool: latency + speed | **[unverified]** (no license file found via API) |
| **cf2dns** | China (ddgth) | [ddgth/cf2dns](https://github.com/ddgth/cf2dns) (~5.2k stars) | Consumes third-party优选 APIs (wetest.vip / hostmonit) and writes per-ISP (CM/CU/CT) A/AAAA records to DNSPod/Aliyun — the "automation" layer above scanners | **[unverified]** |
| **cf-best-ip** | China | [Be90nia/cf-best-ip](https://github.com/Be90nia/cf-best-ip) | Cloudflare Worker that aggregates 18 community优选 sources, validates them against official CIDRs, syncs DNS | MIT |
| **CFSTAPP / cloudflare-ip-tester-app** | China | [Hsia97/CFSTAPP](https://github.com/Hsia97/CFSTAPP), [xianshenglu/cloudflare-ip-tester-app](https://github.com/xianshenglu/cloudflare-ip-tester-app) | Android GUIs wrapping CFST | **[README-only]** |
| **Spedoske/CloudflareScanner** | China | [Spedoske/CloudflareScanner](https://github.com/Spedoske/CloudflareScanner) | Early CFST alternative (latency + speed) | **[unverified]** |
| **cf-knife / CF-IP-Scanner** | Iran | see above | Iranian tools that do CDN-clean-IP scanning too (TLS + colo trace + speed) | see above |
| **Russian CDN equivalents** | Russia | — | None found of comparable prominence; the Russian community concentrates on WARP endpoints (warpscout, awarp, warpfind, AmneziaWG guides like [niksus23/Endpoint-AmneziaWG](https://github.com/niksus23/Endpoint-AmneziaWG)) rather than CDN clean IPs. Flagged as a gap in this research. | — |

### Registration / config tooling (context)

| Tool | Repo | Notes | License |
|---|---|---|---|
| **wgcf** | [ViRb3/wgcf](https://github.com/ViRb3/wgcf) (~8.9k stars) | The reference unofficial WARP registration CLI. Register → generate WireGuard profile. API: `https://api.cloudflareclient.com/v0a884/reg`, User-Agent `1.1.1.1/…` or `okhttp/3.12.1`, `CF-Client-Version` header, TLS 1.2 only, uTLS-fingerprinted ClientHello; mismatched fingerprint ⇒ HTTP 403 (error 1020). Verified in [cloudflare/api.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go) and [cloudflare/url/url.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/url/url.go) | MIT |
| **fscarmen/warp** | [gitlab.com/fscarmen/warp](https://gitlab.com/fscarmen/warp) | Bash menu for WARP on VPS; historically included endpoint optimization (standard ports `[500,1701,2408,4500]` — changelog 2023.3.26; **removed 2025.8.11** "适应官方调整"), MTU optimization, WARP API wrapper | GPL-3.0 |
| **warp-reg.sh** | [chise0713/warp-reg.sh](https://github.com/chise0713/warp-reg.sh) | One-shot registration printing a JSON with keys, endpoint v4/v6, and the `reserved` array (client-id bytes) | GPL-3.0 |
| **badafans/warp-reg** | [badafans/warp-reg](https://github.com/badafans/warp-reg) | Documents the raw registration HTTP exchange: `POST /v0a2158/reg`, `CF-Client-Version: a-6.10-2158`, `User-Agent: okhttp/3.12.1` ([official-warp-api.txt](https://github.com/badafans/warp-reg/blob/main/official-warp-api.txt)) | **[unverified]** |

---

## 2. Techniques, verified in source

### 2.1 What IP ranges do WARP scanners probe?

The default WARP endpoint is `engage.cloudflareclient.com`, which resolves to **`162.159.192.1`** and **`2606:4700:d0::a29f:c001`** (verified locally via DNS, 2026-11). The first /24 of each is the canonical endpoint pool; tools differ in how far they extend.

**warp-plus** — `WarpPrefixes()` in [warp/endpoint.go](https://github.com/bepass-org/warp-plus/blob/master/warp/endpoint.go):

```text
162.159.192.0/24   162.159.195.0/24
188.114.96.0/24    188.114.97.0/24
188.114.98.0/24    188.114.99.0/24
2606:4700:d0::/64  2606:4700:d1::/64
```
(Note: 192 and **195**, not 193; the "162.159.193.x" range often quoted in older guides was not in warp-plus's list at verification time.)

**warpscout** — `poolsV4` in [pools.go](https://github.com/vernette/warpscout/blob/master/pools.go): the six /24s above **plus eight newer 8.x pools**:

```text
8.6.112.0/24  8.34.70.0/24  8.34.146.0/24  8.35.211.0/24
8.39.125.0/24 8.39.204.0/24 8.39.214.0/24  8.47.69.0/24
```
IPv6: `2606:4700:d0::/48` and `2606:4700:d1::/48` (wider than warp-plus's /64 — it samples 256 random addresses per /48 per run, see `expandV6`).

**awarp (Skiro1)** — **[README-only]**: base 10 subnets = `162.159.192.0/21` (covers .192–.199), `188.114.96.0/20` (covers .96–.111), plus the same eight 8.x /24s; `--full-as` adds `162.159.200.0/21`→`162.159.248.0/21` and `188.114.112.0/20`→`188.114.240.0/20` (~60k IPs total). warpscout similarly credits [ampetelin/warp-endpoint-checker](https://github.com/ampetelin/warp-endpoint-checker) for its IPv4 subnet list and [TheyCallMeSecond/WARP-Endpoint-IP](https://github.com/TheyCallMeSecond/WARP-Endpoint-IP) for IPv6.

**Chinese scripts** (MiSaturo, TheyCallMeSecond, rwkgyg/CFwarp, azavaxhuman — verified in `endip.sh`/`ip.sh`): generate N random IPs from `162.159.192/193/195.x` and `188.114.96/97/98/99.x` (one adds `162.159.204.x`), IPv6 from `2606:4700:d0::` / `d1::` random hextets.

**XIU2 CFST** — bundled [ip.txt](https://github.com/XIU2/CloudflareSpeedTest/blob/master/ip.txt) is Cloudflare's *published CDN* ranges (starting `173.245.48.0/20`, `103.21.244.0/22`, … `104.16.0.0/12`, `172.64.0.0/17…` — matching [cloudflare.com/ips-v4](https://www.cloudflare.com/ips-v4/)), not the WARP endpoint ranges. Its IPv6 file was hand-built from bgp.he.net AS13335 prefixes **[README-only]**. warp-plus's `statute.DefaultCFRanges()` ([statute.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/statute/statute.go)) also contains the full published list (15 IPv4 + 7 IPv6), but the *scan path* overrides it with the narrower `WarpPrefixes()` ([wiresocks/scanner.go](https://github.com/bepass-org/warp-plus/blob/master/wiresocks/scanner.go)) — i.e., scanning all published CDN ranges with WG handshakes would be pointless; only the endpoint /24s answer.

### 2.2 What ports?

**The canonical 55/56-port list** — `WarpPorts()` in [warp/endpoint.go](https://github.com/bepass-org/warp-plus/blob/master/warp/endpoint.go) (verified; awarp's "54 ports" **[README-only]** and UMBRA's "55-port canonical list" **[README-only]** are the same family):

```text
500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070,
1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854,
4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
8742, 8854, 8886
```
`2408` (default, from `engage.cloudflareclient.com:2408`), `500`, `1701`, `4500` (the "standard four" used by fscarmen and old guides) are the most reliable; 894, 908, 928… fill out the list. warp-plus picks a **random port per probe** (`RandomWarpPort()` in [ping/warp.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/ping/warp.go)); warpscout instead runs a **port-discovery phase** (common ports first, full sweep only if none answer — [docs/en/how-it-works.md](https://github.com/vernette/warpscout/blob/master/docs/en/how-it-works.md)).

TCP ports for MASQUE/Zero-Trust variants: `443` with SNI `consumer-masque.cloudflareclient.com` / `zt-masque.cloudflareclient.com`, plus documented team-edge IPs `162.159.197.2`/`162.159.198.2` **[README-only]** ([BlizzardSaber/zerotrust-warp-masque](https://github.com/BlizzardSaber/zerotrust-warp-masque), warp-plus MASQUE logs in [issue #307](https://github.com/bepass-org/warp-plus/issues/307)).

### 2.3 The probe itself: real WireGuard handshake vs. naive UDP

The decisive design fork. warp-plus's maintainer admitted the naive approach fails ("The reason for these errors is that the scanner has a very serious problem", [issue #120](https://github.com/bepass-org/warp-plus/issues/120)), and awarp documents why: **WARP servers silently drop Initiation packets whose MAC1 doesn't match a registered key** — an unregistered MAC1-only probe "always finds 0 endpoints" **[README-only]** ([Skiro1/warp-cli README](https://github.com/Skiro1/warp-cli)).

**warp-plus handshake probe** — [ipscanner/ping/warp.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/ping/warp.go), `initiateHandshake()`:

1. Builds a full **Noise_IKpsk2** initiation with the *registered WARP identity's* static key (keys come from the user's own WARP registration — `opts.Scan.PrivateKey`/`PublicKey` from `warp.LoadOrCreateIdentity`, [app/app.go](https://github.com/bepass-org/warp-plus/blob/master/app/app.go)).
2. **UDP "warmup" trick**: before the handshake it sends **20–50 random junk packets of 40–100 bytes, 80–150 ms apart** (`numPackets := randomInt(20, 50)`, sleep loop). This is the DPI-warmup/noise pattern — BPB-Warp-Scanner exposes it as a user-visible option ("scan with or without UDP noise… Random, Packet 50-100, Delay 1-5 ms, Count 5" — [README](https://github.com/bia-pain-bache/BPB-Warp-Scanner)), and warpscout/AmneziaWG generalize it into `jc/jmin/jmax/s1-s4/h1-h4/i1-i5` junk parameters with profile presets (`-gen-i1 quic|dns|sip|stun|random` — [README](https://github.com/vernette/warpscout)).
3. Sends the 148-byte initiation (`0x01` type, sender index 28, TAI64N timestamp, BLAKE2s MAC1 keyed with `"mac1----" + peerPublicKey`).
4. Reads up to 92 bytes with a **5-second deadline**; validates: `response[0] == 2` (response type), `ourIndex == 28`, decrypts payload via the noise state (empty payload expected). RTT = time from initiation send to valid response.

**warpscout's richer validation** ([docs/en/how-it-works.md](https://github.com/vernette/warpscout/blob/master/docs/en/how-it-works.md)): a handshake alone isn't enough on filtering networks. Phase 2 brings up a **real tunnel** per surviving endpoint and fetches `https://speed.cloudflare.com/meta` through it, which yields `SEEN AS` country, colo/node, and location. With `-P` it pings `1.1.1.1` **in-tunnel** with a **burst of 10 echoes** and detects "torn down" endpoints by looking at the **tail of consecutive losses** (DPI kills the tunnel mid-stream; a short burst misses it). Default `-n 5` samples per subnet, `-t 2s` timeout, **10 concurrent tunnels** (`-jt 10`), optional `-speed` in-tunnel download test.

**CFST's probe is much simpler** — it's a CDN tool, not WARP: plain `net.DialTimeout("tcp", ip:443, 1s)` handshake-time measurement, `PingTimes=4`, averaged ([task/tcping.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/tcping.go)).

### 2.4 Latency measurement & result ranking

- **warp-plus**: RTT = WireGuard handshake round-trip only. Results feed a **bounded, RTT-sorted queue**: size 8 (`IPQueueSize`), TTL 30 s (`IPQueueTTL`), target RTT threshold 400 ms (`MaxDesirableRTT`) ([ipscanner/scanner.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/scanner.go), [engine/queue.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/engine/queue.go)). The scan stops when the queue is full of sub-threshold entries; expired entries trigger a rescan. The production scan ([wiresocks/scanner.go](https://github.com/bepass-org/warp-plus/blob/master/wiresocks/scanner.go)) waits until ≥2 endpoints qualify, with a **hard 1-minute context timeout**.
- **warpscout**: ranks by endpoint ping, then in-tunnel ping/loss, filters by node/country (`-exclude-node DME` is the Russian use case: since April 2026 the Moscow `DME` node is DPI-filtered **[README-only]**).
- **awarp**: two-phase — ICMP ping all IPs, then handshake-probe the top-30 fastest on all 54 ports **[README-only]**.
- **UMBRA**: additionally requires **in-tunnel ICMP echo** after handshake ("a TCP connect was never proof of an endpoint" — its v3.8 notes **[README-only]**).

### 2.5 IP iteration / parallelism

- **warp-plus** uses a **full-period LCG** (Hull-Dobell theorem satisfied so the sequence covers every address exactly once before repeating) to walk each CIDR in a deterministic-but-shuffled order — [ipscanner/iterator/iterator.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/iterator/iterator.go). Subnet order is itself shuffled with crypto/rand; after exhaustion it reshuffles and continues forever. This is the most elegant enumeration in the ecosystem and worth copying.
- Its engine processes **one IP per batch per subnet** sequentially ([engine/engine.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/engine/engine.go)) — modest concurrency; tools like awarp use 50 goroutines **[README-only]**, warpscout 10 tunnels, CFST 200 threads.
- **CFST**: for each CIDR it tests **one random last octet per /24** (or all with `-allip`); IPv6 sampling randomizes the tail bytes ([task/ip.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/ip.go)). Concurrency via buffered-channel semaphore: default **200 workers**, hard max **1000**.
- **warpscout**: `expandV4` shuffles each subnet and takes N samples; `-f` full enumeration; caps Go heap at 32 MiB so routers don't OOM.

### 2.6 CDN speed-test methodology (CFST — verified in source)

Pipeline ([README](https://github.com/XIU2/CloudflareSpeedTest), [main.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/main.go)):

1. **Latency phase** (TCPing default): `net.DialTimeout` to `ip:443`, **1 s timeout**, **4 attempts**, mean delay; failed attempts ⇒ loss. 200 concurrent workers.
   - HTTPing alternative: HTTP HEAD via a custom `DialContext` that **pins the resolved IP** (hosts-file emulation — `getDialContext` in [task/download.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/download.go)), **2 s timeout**, valid codes 200/301/302; extracts the **colo (IATA code) from the `cf-ray` response header** and can filter by it (`-cfcolo HKG,FRA,...`). Multi-CDN colo parsing for CloudFront (`x-amz-cf-pop`), Fastly (`x-served-by`), CDN77 (`x-77-pop`), Bunny, Gcore ([task/httping.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/httping.go)).
2. **Filter**: delay upper/lower bounds (`-tl 200 -tll 40`), loss cap (`-tlr 0.2`).
3. **Download phase**: sequential (single-threaded queue) over the lowest-latency IPs, GET on a large file (default `https://cf.xiu2.xyz/url`, a redirector to community mirrors; `https://speed.cloudflare.com/__down?bytes=…` is the recommended self-hosted alternative), **10 s per IP**, EWMA moving-average speed ([task/download.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/download.go)); stops when `-dn 10` results meet `-sl` speed floor.
4. **Known gotchas** (README): first-run latency inflated; any local TUN-mode proxy falsifies TCPing to ~0 ms; results include **origin/return IPs** that pass TCP but fail HTTP — filter with `-sl 0.01`; HTTPing at high concurrency **triggers Cloudflare/ISP temporary rate-limiting** (README warns to lower `-n`); the colo of an anycast IP changes per network/region/time.

### 2.7 WARP-account bootstrapping (context)

Scanners that need a registered key (warp-plus, warpscout, UMBRA, BPB) all follow the wgcf recipe: `POST https://api.cloudflareclient.com/v0a<build>/reg` with an Android-app User-Agent (`okhttp/3.12.1` / `1.1.1.1/6.38.9`), `CF-Client-Version`, TLS 1.2, a Curve25519 pubkey, and `tos` timestamp; response yields device id, token, license, and `client_id` whose 3 bytes become the WireGuard `reserved` field ([wgcf cloudflare/api.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go), [wgcf url.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/url/url.go), [badafans/warp-reg official-warp-api.txt](https://github.com/badafans/warp-reg/blob/main/official-warp-api.txt), warp-reg.sh sample output). Current API version in wgcf master: `v0a884`.

---

## 3. Legal / ethical norms observed by these tools

- **Scan only Cloudflare's own published / endpoint ranges.** Every tool confines itself to [cloudflare.com/ips](https://www.cloudflare.com/ips/) ranges or the WARP endpoint pools (themselves within Cloudflare AS13335 space, per bgp.he.net). warpscout even **rejects user-supplied targets wider than /20** (`targetMinBitsV4` in [pools.go](https://github.com/vernette/warpscout/blob/master/pools.go)) to prevent abuse.
- **Authentication, not exploitation.** Handshake probes use a *legitimately registered* WARP identity — the same packets the official client sends, to endpoints Cloudflare publishes for client use. No data exfiltration, no account abuse, no credential stuffing.
- **Bounded volume.** Defaults are small: warpscout 5 IPs/subnet × 14 subnets, warp-plus queue of 8, CFST one random IP per /24. CFST's README explicitly warns that high-concurrency HTTPing triggers temporary blocking and advises lowering concurrency — i.e., the norm is *stay under Cloudflare's abuse thresholds*.
- **Explicit disclaimers.** puzige: "not affiliated with or endorsed by Cloudflare… comply with their terms of service". wgcf: non-affiliation notice + ToS prompt before register. CFST/cf2dns READMEs carry the community's own warning that **Cloudflare explicitly prohibits using 优选IP for proxy/CDN-fronting purposes** (cf2dns cites the Dec 2024 policy statement) — our tool should carry a similar notice.
- **No third-party targets.** None of these tools scan ranges belonging to other networks (the Iranian multi-CDN tools add Akamai/Fastly ranges only from those CDNs' own published blocks — UMBRA cites Akamai's published edge list).

---

## 4. What our tool should adopt

For the Rust rewrite (warp-scan + cdn-scan modules), ranked by leverage:

### warp-scan module

1. **Real Noise_IKpsk2 handshake probe with a registered identity** (warp-plus `initiateHandshake` model). This is the single most important correctness decision: naive UDP reachability yields false positives, and MAC1-only probes yield all negatives. In Rust, boringtun's handshake-state machinery gives us this (QMahyar/cf-scanner already demonstrates the pattern: Init with MAC1, accept 92-byte Response *or* 64-byte Cookie as "open").
2. **The canonical pool list**: warp-plus's six /24s + warpscout's eight 8.x /24s + `2606:4700:d0::/48` and `d1::/48`, IPv4+IPv6 toggleable. Ship as a bundled, refreshable list (like `cf-scanner ranges refresh`).
3. **The 55-port list** as default, with three modes: pinned port (2408), "standard four" sweep (500/1701/2408/4500), full sweep. Random port per probe (warp-plus) for anti-fingerprinting, or port-discovery phase first (warpscout) for efficiency — expose both.
4. **Junk/noise before handshake** as a first-class option (BPB's defaults: random 50–100 byte packets, 1–5 ms delay, 5 count; warp-plus: 20–50 packets, 40–100 bytes, 80–150 ms). For DPI-heavy networks, AmneziaWG-style `jc/jmin/jmax/s1-s4/h1-h4/i1` profiles with presets (quic/dns/sip/stun/random) — the warpscout `find-junk` search loop is the state of the art.
5. **RTT-sorted bounded result queue** (warp-plus: size 8, TTL 30 s, RTT ceiling 400 ms) instead of unbounded accumulation — cheap, and it makes "scan until N good endpoints" trivial.
6. **Full-period LCG enumeration** per CIDR (warp-plus iterator) — uniform, non-repeating, shuffleable order without materializing IP lists; works for /24s and /48s alike.
7. **Optional deep validation tier** (warpscout `-P` model): bring up the tunnel, in-tunnel ping 1.1.1.1 with a 10-echo burst, tail-loss "torn down" detection, optional `speed.cloudflare.com/meta` fetch to report colo + exit country. Rank-2 feature: without it, filtered networks report endpoints that die after one handshake.
8. **Operational hygiene**: hard wall-clock scan timeout (warp-plus: 1 min default), concurrent-tunnel cap (~10), sample-per-subnet default (~5), memory cap for router use, live TUI table, JSON/CSV/report-file output.
9. **MASQUE fallback probes** (TCP 443, SNI `consumer-masque.cloudflareclient.com`; find-SNI loop) — needed where UDP is fully dropped (China per BlizzardSaber's measurements; increasingly elsewhere).

### cdn-scan module

1. **CFST's two-tier pipeline**: TCP-handshake latency (port 443, 1 s timeout, 4 tries, mean) → filter (delay bounds + loss cap) → sequential download-speed tier over top-N (10 s, EWMA), stop-at-target. Proven against ~30k users' networks; edge cases already documented.
2. **Ranges from cloudflare.com/ips-v4 + ips-v6** (bundled + refreshable, cf. `cf-scanner ranges refresh`), one random IP per /24 by default with opt-in full enumeration (`-allip`).
3. **HTTPing mode with colo extraction** from `cf-ray` (plus the multi-CDN header table CFST implements) and `-cfcolo` filtering — the killer feature for China/Iran where users want a specific region.
4. **IP pinning via custom DialContext** (hosts-file emulation) so HTTP tests actually hit the scanned IP — non-negotiable for correctness, easy in Rust with `hyper`/`reqwest` `resolve()` or a custom connector.
5. **Anti-gotcha features CFST learned the hard way**: warm-up run, origin-IP filtering (speed ≥ 0.01 MB/s), detect-proxy warning (near-zero latency), concurrency defaults low enough (≤200) to avoid triggering Cloudflare's temporary blocks, `Connection: close` on last request, idle-connection draining (PR #645).
6. **Colo/trace endpoint**: `/cdn-cgi/trace` on any scanned IP for cheap colo confirmation without full HTTPing.
7. **Shared infrastructure with warp-scan**: same range provider, same concurrency semaphore, same result queue, same output formats (CSV/JSON/table).

### Deliberately not adopting

- Third-party优选 APIs (cf2dns/wetest) — supply-chain trust issues; scan locally instead.
- ICMP phase as a hard prerequisite (awarp) — ICMP is often blocked; TCP/TLS or handshake probes are the reliable primitive.
- DNS-record automation (cf2dns) — out of scope for a scanner; keep the tool read-only toward the network.
- Cloning/license tricks (fscarmen history) — ToS-hostile, removed even there.

---

## 5. Sources & verification notes

**Verified in source code (fetched raw):**
- [bepass-org/warp-plus: warp/endpoint.go](https://github.com/bepass-org/warp-plus/blob/master/warp/endpoint.go) (prefixes, 54-port list), [ipscanner/ping/warp.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/ping/warp.go) (handshake + warmup), [ipscanner/scanner.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/scanner.go) (defaults), [ipscanner/engine/queue.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/engine/queue.go) + [engine.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/engine/engine.go), [ipscanner/iterator/iterator.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/iterator/iterator.go) (LCG), [ipscanner/statute/statute.go](https://github.com/bepass-org/warp-plus/blob/master/ipscanner/statute/statute.go) (DefaultCFRanges), [wiresocks/scanner.go](https://github.com/bepass-org/warp-plus/blob/master/wiresocks/scanner.go) (1-min timeout, 2 endpoints), [app/app.go](https://github.com/bepass-org/warp-plus/blob/master/app/app.go)
- [XIU2/CloudflareSpeedTest: task/tcping.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/tcping.go), [task/httping.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/httping.go), [task/download.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/download.go), [task/ip.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/task/ip.go), [main.go](https://github.com/XIU2/CloudflareSpeedTest/blob/master/main.go), [ip.txt](https://github.com/XIU2/CloudflareSpeedTest/blob/master/ip.txt), [README.md](https://github.com/XIU2/CloudflareSpeedTest/blob/master/README.md)
- [vernette/warpscout: pools.go](https://github.com/vernette/warpscout/blob/master/pools.go), [docs/en/how-it-works.md](https://github.com/vernette/warpscout/blob/master/docs/en/how-it-works.md), [README.md](https://github.com/vernette/warpscout)
- [ViRb3/wgcf: cloudflare/api.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go), [cloudflare/url/url.go](https://github.com/ViRb3/wgcf/blob/master/cloudflare/url/url.go)
- [MiSaturo/WarpScanner point/endip.sh](https://github.com/MiSaturo/WarpScanner/blob/main/point/endip.sh), [TheyCallMeSecond/WARP-Endpoint-IP ip.sh](https://github.com/TheyCallMeSecond/WARP-Endpoint-IP/blob/main/ip.sh) (random-IP generation ranges)
- [badafans/warp-reg official-warp-api.txt](https://github.com/badafans/warp-reg/blob/main/official-warp-api.txt)
- [cloudflare.com/ips](https://www.cloudflare.com/ips/) (live fetch)
- DNS: `engage.cloudflareclient.com` → 162.159.192.1 / 2606:4700:d0::a29f:c001 (resolved 2026-11)

**README-only (not source-verified):** oblivion/oblivion-desktop internals; BPB-Warp-Scanner internals & license; Skiro1/warp-cli scan phases/port count; awarp full-AS subnet math; UMBRA's ranges/ports claims; arshiacomplus, Ptechgithub, cf-knife, CF-IP-Scanner, Shellgate, DarknessShade, warpfind details; warpscout's DME-filtering claim (April 2026, plausibly current but only their README states it); CFST's `-cfcolo` DME/community endpoint lists (ircfspace/endpoint).

**Not found / gaps:** no prominent Russian CDN-clean-IP tool; no source-level verification obtained for puzige/CloudflareWarpSpeedTest's port-sweep implementation (README credits only); CFST download-test default URL is a rotating redirector — its upstream mirrors change frequently (discussion #490).
