# async-http-client-check

**Offline checker for the 21 repository-level security advisories of
`org.asynchttpclient:async-http-client` (AsyncHttpClient, "AHC").**
It tells you which ones your jar is actually exposed to, flags the ones **Dependabot and OSV
cannot see**, and gives one answer per line: **`3.0.13`** (3.x) / **`2.16.1`** (2.x).

Single jar, zero runtime dependencies, fully offline, Java 17+.

---

## Why this exists

### 1. 17 advisories were published on 2026-08-09 — the global database has 4 of them

On 2026-08-09 the AsyncHttpClient maintainers published **17** security advisories on the project's
own repository (`AsyncHttpClient/async-http-client` → *Security* → *Advisories*).

Dependabot and OSV do not read that page. They read the **GitHub global advisory database**. As of
2026-09-19 that database contains only **4** of the 17 (`CVE-2026-85716`, `CVE-2026-85717`,
`CVE-2026-85720`, `CVE-2026-85721`, all added on 2026-09-17). The other **13** return `404` from
`GET /advisories/<GHSA>`; two of those 13 even have CVE IDs (`CVE-2026-85718`, `CVE-2026-85719`).

Including the four older advisories (`CVE-2024-53990`, `CVE-2026-40490`, `CVE-2026-45300`,
`CVE-2026-55688`), the repository lists 21; the global database has 8.

### 2. The version Dependabot tells you to install is itself affected by 5 of them

Compute "the version that clears everything" from the global database and the 3.x answer is
**`3.0.12`**. OSV agrees: `POST /v1/query` for `3.0.12` returns **zero** vulnerabilities.

The repository advisories say `3.0.12` is still inside the range of five:

| Advisory | Severity | What | Needs |
|---|---|---|---|
| `GHSA-rqf5-2wxv-rjf4` | high | A Digest challenge without a usable nonce is answered with `Authorization: Basic`, i.e. the password in base64 | A Digest `Realm` (server or proxy auth) |
| `GHSA-jmqq-x5g9-9p2w` | high | When a request is replayed to a **different** host, the first host's request / credentials go to the second host | Replay to another host (a failover `ResponseFilter` or the IOException retry path) **and** credentials or a proxy |
| `GHSA-vvp4-63h8-v5pm` | medium | NTLM / Negotiate connections are reused across principals | NTLM or Negotiate with per-request credentials |
| `GHSA-f9m8-cv68-674w` | medium | Cookie `Domain` is not checked against the public suffix list (`Domain=co.uk`) | A shared `CookieStore` across origins |
| `GHSA-qhv6-3pmh-95q4` | low | `qop="auth-int"` switches Digest mutual authentication off (3.0.12 only) | Digest auth |

**Be precise about the two high ones:** they leak credentials, but **only if you configured
credentials** (a `Realm`, Digest/NTLM, or a proxy) — and `GHSA-jmqq` additionally needs a replay to a
different host. A client doing plain unauthenticated GETs is not exposed to them. This tool does not
know how you use the client; it reports what the version range says and leaves the call to you.

The maintainers say it themselves in the text of `CVE-2026-85721`:

> Note that 3.0.12 is itself affected by a separate issue, GHSA-rqf5-2wxv-rjf4 … Upgrade to 3.0.13
> to pick up both fixes.

So on 3.x: **Dependabot says `3.0.12`, and after you upgrade it shows green. The real answer is
`3.0.13`.** On 2.x the answer is `2.16.1` either way — but 13 of the advisories behind it are
still invisible to your scanner.

### 3. The decompression bomb needs no configuration

`CVE-2026-85721` (high) is the one that applies to **default settings**: automatic response
decompression is on by default, and the HTTP/1.1 path inflates the body with no limit on total size.
A malicious or compromised server — or anyone able to modify the response in transit — can send a
small gzip/deflate body that exhausts the heap. Affected: `<= 3.0.11` and `<= 2.16.0`.
This one *is* in the global database, so Dependabot does alert on it.

### Boundaries are not written consistently

The ranges mix `>=`, `<=`, `<`, an explicit `= 3.0.12`, and a bare `3.0.0`. The same `3.0.11` is
**safe** for `CVE-2026-55688` (`< 3.0.11`) and **affected** for `GHSA-v9f2-7rw2-gr2x`
(`<= 3.0.11`). The rule table keeps every operator exactly as written; an assertion in
`tools/gen_rules.py` and a unit test fail if the boundary stops behaving this way. Any range
fragment the parser does not recognise is an error — never "not affected".

Where the repository and the global database both carry an advisory but disagree, the rule table
takes the **union**. Today that is one case: `CVE-2024-53990` — the repository only lists the 3.x
version `3.0.0`, the global database also lists 2.x `>= 2.1.0, < 2.12.4`. Trusting only one side
would under-report.

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
java -jar async-http-client-check.jar --version-of 3.0.12     # judge a version directly
```

Each hit prints the ID (CVE if there is one, otherwise GHSA), severity, title, fixed version, and
**`Dependabot/全局库:未收录`** ("not in the global database") where applicable. The output is in
Chinese.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Not affected by any of the 21, **and every file was actually read** |
| `1` | Affected |
| `2` | Could not judge — bad arguments, no AHC jar found, unrecognised version, or a pre-release version that falls outside the published ranges |
| `4` | **Some file could not be read** — not a zip, truncated, or an I/O failure |

"I could not read it" and "you are safe" must be two different sentences. A legitimately empty jar
(a bare 22-byte EOCD record) is not a read failure. If a file is affected *and* another is unreadable,
the exit code stays `1`.

## What it does not tell you

- **Only these 21 advisories, only `async-http-client`.** Netty CVEs in the Netty jars AHC depends
  on are not covered.
- **Reachability is not checked.** Most of the 2026-08-09 advisories need authentication, a proxy,
  WebSocket, cookies or resumable downloads to matter. Severity is printed as published.
- **The information gap is temporary.** GitHub may add the missing 13 to the global database at
  any time. `tools/recheck_before_publish.py` checks whether it still exists.

## How the rule table is built

`src/main/java/dev/mikko/ahccheck/RuleTable.java` is **generated**, never hand-edited:

```bash
python tools/gen_rules.py --dry   # run the assertions only
python tools/gen_rules.py         # regenerate the table
```

It reads the repository-level advisories (`vulnerable_version_range`, `patched_versions`), looks up
each one in the global database, and records "visible to Dependabot: yes/no" as a field of every
rule. Seven assertions must pass or nothing is written: the advisory count and the exact set of 13
missing from the global database still match the baseline; the intersections are still `3.0.13` /
`2.16.1` (and `3.0.12` when computed from the global database alone); those versions return `200`
from Maven Central while a sentinel version returns `404`; `3.0.12` still hits at least one high
advisory and none of those are in the global database; all operator styles are present and the
boundary case still flips; and the repository/global disagreement is still exactly the known one.

Real-jar end-to-end checks live in `tools/e2e_real_jars.py` (actual jars from Maven Central,
including a fat-jar and a WAR). `tools/recheck_before_publish.py` re-verifies the gap —
global database, OSV and Maven Central, each with a positive control and a sentinel — and exits
non-zero if anything moved.

## License

Apache License 2.0 — see `LICENSE`.
