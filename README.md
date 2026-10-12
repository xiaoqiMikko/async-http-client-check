# async-http-client-check

**Offline checker for the 26 repository-level security advisories of
`org.asynchttpclient:async-http-client` (AsyncHttpClient, "AHC").**
It tells you which ones your jar is actually exposed to, flags the ones **Dependabot and OSV
cannot see**, and gives one answer per line:

- **3.x → `3.0.14`**
- **2.x → there is no clean 2.x version.** The 2.x line is end of life; its last release `2.16.1`
  is still affected by 5 advisories that will not be fixed. The only fix is moving to `3.0.14`.

Single jar, zero runtime dependencies, fully offline, Java 17+.

> **Correction (2026-10-12, v0.2.0).** v0.1.0 of this tool and README said: "the global database
> lists only 4 of the 17", "Dependabot tells you to install 3.0.12", "the real answer is
> `3.0.13` / `2.16.1`". All three were true on 2026-09-19 and **none is true any more**:
> upstream published 5 more advisories on 2026-09-24 (fixed in `3.0.14`, not fixed on 2.x), and
> on 2026-10-08 the GitHub global database picked up 9 more entries. **v0.1.0 reports `3.0.13`
> and `2.16.1` as clean — they are not. Use v0.2.0.**

---

## Why this exists

### 1. The 2.x line is end of life, and its last release is still affected

On 2026-09-24 the maintainers published five advisories. Each one ends its *Patches* section with
the same sentence:

> The 2.x line is end of life and will not receive a fix. Upgrade to 3.0.14.

All five list a 2.x range that ends at `2.16.1` — the newest 2.x release on Maven Central — with
an empty fixed version:

| Advisory | Severity | 2.x range | What | Needs |
|---|---|---|---|---|
| `CVE-2026-107230` | high | `>= 2.0.0, <= 2.16.1` | Pooled connections are still shared across NTLM / Negotiate / proxy logins (incomplete fix of `GHSA-vvp4-63h8-v5pm`) | NTLM, Kerberos or SPNEGO to an origin or proxy, or any login on a SOCKS / CONNECT proxy, **and** requests under different identities through one client. Basic and Digest to an origin are not affected |
| `CVE-2026-107227` | high | `>= 2.2.0, <= 2.16.1` | WebSocket `permessage-deflate` messages are inflated with no size limit | `setEnablewebSocketCompression(true)` — **off by default** — and an untrusted or cleartext WebSocket server |
| `CVE-2026-107228` | medium | `>= 2.1.0, <= 2.16.1` | A `Cookie` header set with `setHeader` / `addHeader` is replaced by the cookie store's cookies (bypass of the `CVE-2024-53990` fix) | The cookie store, **on by default**, holding any cookie for that origin |
| `CVE-2026-107226` | medium | `>= 2.1.0, <= 2.16.1` | A cookie received over plaintext HTTP can plant, overwrite or delete a `Secure` cookie set over HTTPS | One cookie store shared between plaintext and HTTPS origins of the same site |
| `CVE-2026-107229` | medium | `>= 2.16.0, <= 2.16.1` | Incomplete origin checks in the default cookie store (public-suffix private section, IP hosts, …) | One client reaching several origins, one of them attacker-influenced |

**Be precise about the two high ones:** neither applies to a client doing plain requests with
default settings. `CVE-2026-107227` needs WebSocket compression switched on; `CVE-2026-107230`
needs NTLM / Kerberos / SPNEGO or an authenticating proxy. The three medium ones are the ones that
touch the default cookie store. This tool does not know how you use the client; it reports what
the version range says and leaves the call to you.

What it does change: **"upgrade to 2.16.1" is no longer an answer.** An older 2.x version such as
`2.12.3` can be moved up to `2.16.1` to clear the advisories that do have a 2.x fix — and after
that it is still inside the five ranges above (upgrading from below `2.16.0` even *adds*
`CVE-2026-107229`, whose range starts at `2.16.0`). The tool prints exactly that, and exits `1`
for `2.16.1`.

### 2. The global database is still missing 9 of the 26

Dependabot and OSV do not read the project's own *Security → Advisories* page. They read the
**GitHub global advisory database**. As of 2026-10-12, `GET /advisories/<GHSA>` returns `404` for
**9** of the 26 repository advisories:

- 8 of the 17 published on 2026-08-09 (`CVE-2026-107281`, `CVE-2026-107279`, `CVE-2026-107232`,
  `CVE-2026-107284`, `CVE-2026-102740`, `CVE-2026-102737`, `CVE-2026-85718`, `CVE-2026-85719`) —
  two of them rated high by the maintainers (`CVE-2026-107232`, `CVE-2026-85719`), both about
  proxy credentials;
- 1 of the 5 published on 2026-09-24 (`CVE-2026-107229`).

The database has been catching up — 4 of the August batch arrived on 2026-09-17, 5 more on
2026-10-08 — so this number will keep moving. Every hit is printed with
`Dependabot/全局库:已收录 / 未收录` ("in / not in the global database"), and the tool prints the
date its table was generated. `tools/recheck_before_publish.py` tells you whether the gap still
exists today.

For 3.x the practical consequence is small now: computed from the global database alone, the
target is also `3.0.14`. For versions `<= 3.0.11` the two missing high advisories are simply not
shown to you.

One more difference worth knowing: `CVE-2026-107282` is rated **high** by the maintainers and
**critical** in the global database. The rule table keeps the maintainers' rating.

### 3. The decompression bomb needs no configuration

`CVE-2026-85721` (high) is the one that applies to **default settings**: automatic response
decompression is on by default, and the HTTP/1.1 path inflates the body with no limit on total size.
A malicious or compromised server — or anyone able to modify the response in transit — can send a
small gzip/deflate body that exhausts the heap. Affected: `<= 3.0.11` and `<= 2.16.0`.
This one *is* in the global database, so Dependabot does alert on it.

### Boundaries are not written consistently

The ranges mix `>=`, `<=`, `<`, an explicit `= 3.0.12`, and a bare `3.0.0`. The same `3.0.11` is
**safe** for `CVE-2026-55688` (`< 3.0.11`) and **affected** for `CVE-2026-107232`
(`<= 3.0.11`). The rule table keeps every operator exactly as written; an assertion in
`tools/gen_rules.py` and a unit test fail if the boundary stops behaving this way. Any range
fragment the parser does not recognise is an error — never "not affected". An **empty fixed
version** is accepted only when the advisory text itself says the line is end of life; it is
stored as "no fix on this line", never as "not affected".

Where the repository and the global database both carry an advisory but disagree on the range, the
rule table takes the **union**. Today: `CVE-2024-53990` (the repository only lists the 3.x version
`3.0.0`, the global database also lists 2.x `>= 2.1.0, < 2.12.4`) and `CVE-2026-107230` (same
range, written `<= 3.0.13` on one side and `< 3.0.14` on the other).

### And it does not scan `pom.xml` — on purpose

AHC is usually a **transitive** dependency, pulled in by an SDK or client library. The artifactId
may never appear in your `pom.xml`. This tool reads
`META-INF/maven/org.asynchttpclient/async-http-client/pom.properties` inside the jars that actually
ship — including jars nested in a Spring Boot fat-jar (`BOOT-INF/lib`) or a WAR (`WEB-INF/lib`).
The legacy 1.x coordinate `com.ning:async-http-client` has the same artifactId; it is listed but not
judged.

## Usage

```bash
java -jar async-http-client-check.jar target/                 # scan build output
java -jar async-http-client-check.jar myapp.jar               # fat-jar / war, nested jars included
java -jar async-http-client-check.jar --version-of 2.16.1     # judge a version directly
```

Each hit prints the ID, severity, title, range, fixed version (or `无(2.x 线已停止维护)` — "none,
the 2.x line is end of life"), and whether the global database has it. The output is in Chinese.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Not affected by any of the 26, **and every file was actually read** |
| `1` | Affected — **including `2.16.1`**, which v0.1.0 reported as `0` |
| `2` | Could not judge — bad arguments, no AHC jar found, unrecognised version, or a pre-release version that falls outside the published ranges |
| `4` | **Some file could not be read** — not a zip, truncated, or an I/O failure |

"I could not read it" and "you are safe" must be two different sentences. A legitimately empty jar
(a bare 22-byte EOCD record) is not a read failure. If a file is affected *and* another is unreadable,
the exit code stays `1`.

## What it does not tell you

- **Only these 26 advisories, only `async-http-client`.** Netty CVEs in the Netty jars AHC depends
  on are not covered.
- **Reachability is not checked.** Most of these advisories need authentication, a proxy,
  WebSocket, cookies or resumable downloads to matter. Severity is printed as published by the
  maintainers.
- **It is a snapshot.** The table was generated on the date the tool prints. Upstream may publish
  more advisories, release `3.0.15`, or the global database may add the missing ones — this
  already happened once (see the correction at the top).
- **It does not tell you how to migrate from 2.x to 3.x.** That is a major-version upgrade; read
  the upstream release notes.

## How the rule table is built

`src/main/java/dev/mikko/ahccheck/RuleTable.java` is **generated**, never hand-edited:

```bash
python tools/gen_rules.py --dry   # run the assertions only
python tools/gen_rules.py         # regenerate the table
```

It reads the repository-level advisories (`vulnerable_version_range`, `patched_versions`), looks up
each one in the global database, and records "visible to Dependabot: yes/no" as a field of every
rule. Seven assertions must pass or nothing is written: the advisory count and the exact set of 9
missing from the global database still match the baseline; an empty fixed version only appears on
the 2.x line and only where the advisory text carries the end-of-life sentence; the 3.x
intersection is `3.0.14` and the set of five unfixed 2.x advisories is unchanged; those versions
return `200` from Maven Central, a sentinel returns `404`, and Maven Central has no 2.x release
newer than `2.16.1`; `2.16.1` hits exactly those five, `3.0.13` hits five that are all fixed in
`3.0.14`, and `3.0.14` hits none; all operator styles are present and the boundary cases still
flip; and the repository/global disagreements are still exactly the known ones.

Real-jar end-to-end checks live in `tools/e2e_real_jars.py` (actual jars from Maven Central,
including a fat-jar and a WAR). `tools/recheck_before_publish.py` re-verifies the claims with an
independent source — OSV says `3.0.14` is clean and `2.16.1` is not — plus the global database and
Maven Central, each with a positive control and a sentinel, and exits non-zero if anything moved.

## License

Apache License 2.0 — see `LICENSE`.
