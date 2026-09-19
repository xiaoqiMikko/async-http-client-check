#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""async-http-client-check —— 发布前事实复核。

本工具的全部卖点是一个**信息差**:官方仓库的 advisory 比 Dependabot / OSV 读的全局库多 13 条。
这个信息差会随时间消失(GitHub 补收录、OSV 同步、上游发 3.0.14)。**消失的那天,文案就是错的。**
所以发任何东西之前跑一遍;任一项变了就打印「信息差已变,文案要改」并非零退出。

🔴 每一组都带阳性对照或哨兵 —— 单向判据和没验证长得一模一样:
   · 全局库 404 可能是「真没收」,也可能是 gh 没登录 / 限流 —— 所以同时查一条**必定已收录**的(阳性)
     和一条**必定不存在**的(哨兵)。
   · OSV 返回空可能是「真没有」,也可能是包名/生态拼错 —— 所以同时查 3.0.11(必定非空)。
   · Central 404 可能是「真没有」,也可能是网络挡了 —— 所以同时查必定存在的版本。

四组:
   A  全局 advisory 库仍缺那 13 条(GitHub REST advisories/<GHSA>)
   B  OSV 对 3.0.12 仍返回零漏洞;那 13 条在 OSV 按编号也仍查不到
   C  Central 状态不变:3.0.12 / 3.0.13 / 2.16.1 为 200,3.0.14 仍 404,metadata 的 release 仍是 3.0.13
   D  仓库级原文不变:仍是 21 条;CVE-2026-85721 原文仍写着 3.0.12 自身受 GHSA-rqf5 影响

退出码:0 = 信息差仍在,文案可用;1 = 信息差已变,文案要改;2 = 探针本身坏了(读数作废)。

用法:  python -u tools/recheck_before_publish.py
"""
import json
import subprocess
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG = "org.asynchttpclient:async-http-client"
REPO = "AsyncHttpClient/async-http-client"

MISSING_13 = [
    "GHSA-vvp4-63h8-v5pm", "GHSA-f9m8-cv68-674w", "GHSA-qhv6-3pmh-95q4", "GHSA-jmqq-x5g9-9p2w",
    "GHSA-rqf5-2wxv-rjf4", "GHSA-v9f2-7rw2-gr2x", "GHSA-mfj3-87qq-382v", "GHSA-rwhr-j9rv-85f8",
    "GHSA-3wp9-xfwm-rjjf", "GHSA-cf59-3jcr-vfhw", "GHSA-qpfv-56x8-xgx4", "GHSA-gcmv-gr82-6m8v",
    "GHSA-x5w6-vm3f-pp6f",
]
GLOBAL_POSITIVE = "GHSA-7grg-jcf7-rpmx"        # CVE-2026-85721,09-17 已被全局库收录
GLOBAL_SENTINEL = "GHSA-zzzz-zzzz-zzzz"        # 不存在的编号

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"

CENTRAL = "https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/%s/async-http-client-%s.jar"
CENTRAL_META = "https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/maven-metadata.xml"
EXPECT_200 = ["3.0.12", "3.0.13", "2.16.1"]
EXPECT_404 = ["3.0.14"]
EXPECT_RELEASE = "3.0.13"

EXPECT_REPO_TOTAL = 21
QUOTE_85721 = "3.0.12 is itself affected by a separate issue, GHSA-rqf5-2wxv-rjf4"

changed = []   # 信息差变了 → 文案要改
broken = []    # 探针本身坏了 → 读数作废


def ok(g, m):
    print("  ✅ %-10s %s" % (g, m))


def diff(g, m):
    print("  ❌ %-10s %s" % (g, m))
    changed.append("%s: %s" % (g, m))


def dead(g, m):
    print("  ☠️ %-10s %s" % (g, m))
    broken.append("%s: %s" % (g, m))


def gh_status(path):
    """→ (状态, json 或 None)。状态 200 / 404 / 'ERR'。"""
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
    if r.returncode == 0:
        return 200, json.loads(r.stdout)
    if "HTTP 404" in (r.stderr or ""):
        return 404, None
    return "ERR:" + (r.stderr or "").strip()[:120], None


def http(url, data=None, method=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "ahc-check-recheck", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return "ERR:%s" % e, ""


def osv_query(version):
    body = json.dumps({"package": {"name": PKG, "ecosystem": "Maven"}, "version": version}).encode()
    st, txt = http(OSV_QUERY, data=body, method="POST")
    if st != 200:
        return None
    return [v["id"] for v in json.loads(txt or "{}").get("vulns", [])]


# ------------------------------------------------------------------ A
print("=" * 78)
print("A 组 —— GitHub 全局 advisory 库(Dependabot 读的)是否仍缺那 13 条")
print("=" * 78)
st, _ = gh_status("advisories/" + GLOBAL_POSITIVE)
(ok if st == 200 else dead)("A 阳性", "%s → %s(应 200)" % (GLOBAL_POSITIVE, st))
st, _ = gh_status("advisories/" + GLOBAL_SENTINEL)
(ok if st == 404 else dead)("A 哨兵", "%s → %s(应 404)" % (GLOBAL_SENTINEL, st))
now_in = []
for g in MISSING_13:
    st, _ = gh_status("advisories/" + g)
    if st == 200:
        now_in.append(g)
    elif st != 404:
        dead("A %s" % g, "查询出错:%s" % st)
if now_in:
    diff("A 收录", "全局库新收录了 %d 条:%s —— 「Dependabot 看不见」要改口径" % (len(now_in), ", ".join(now_in)))
else:
    ok("A 收录", "13 条全局库仍然全部 404")
st, lst = gh_status("advisories?ecosystem=maven&affects=%s&per_page=100" % PKG)
if st != 200:
    dead("A 按包查", "查询出错:%s" % st)
else:
    hit = sorted({a["ghsa_id"] for a in lst} & set(MISSING_13))
    (diff if hit else ok)("A 按包查", "按包列出的条目里含那 13 条中的:%s" % (hit or "无"))

# ------------------------------------------------------------------ B
print()
print("=" * 78)
print("B 组 —— OSV 对 3.0.12 是否仍然零漏洞")
print("=" * 78)
pos = osv_query("3.0.11")
if not pos:
    dead("B 阳性", "OSV 对 3.0.11 返回 %s —— 应非空,查询方式本身坏了,本组读数作废" % pos)
else:
    ok("B 阳性", "OSV 对 3.0.11 返回 %d 条(%s)" % (len(pos), ", ".join(sorted(pos))))
v12 = osv_query("3.0.12")
if v12 is None:
    dead("B 3.0.12", "OSV 查询出错")
elif v12:
    diff("B 3.0.12", "OSV 对 3.0.12 现在返回 %d 条:%s" % (len(v12), ", ".join(sorted(v12))))
else:
    ok("B 3.0.12", "OSV 对 3.0.12 仍返回零漏洞")
st, _ = http(OSV_VULN % GLOBAL_POSITIVE)
(ok if st == 200 else dead)("B 按编号阳性", "OSV %s → %s(应 200)" % (GLOBAL_POSITIVE, st))
now_osv = []
for g in MISSING_13:
    st, _ = http(OSV_VULN % g)
    if st == 200:
        now_osv.append(g)
    elif st != 404:
        dead("B %s" % g, "OSV 查询出错:%s" % st)
(diff if now_osv else ok)("B 按编号", "OSV 按编号查得到的:%s" % (now_osv or "无(13 条仍全部 404)"))

# ------------------------------------------------------------------ C
print()
print("=" * 78)
print("C 组 —— Maven Central 状态")
print("=" * 78)
for v in EXPECT_200:
    st, _ = http(CENTRAL % (v, v), method="HEAD")
    (ok if st == 200 else (dead if str(st).startswith("ERR") else diff))("C %s" % v, "HTTP %s(应 200)" % st)
for v in EXPECT_404:
    st, _ = http(CENTRAL % (v, v), method="HEAD")
    if st == 404:
        ok("C %s" % v, "HTTP 404(还没发)")
    elif st == 200:
        diff("C %s" % v, "%s 已经发布 —— 「3.0.13 是答案」要重新核" % v)
    else:
        dead("C %s" % v, "HTTP %s" % st)
st, meta = http(CENTRAL_META)
if st != 200:
    dead("C metadata", "HTTP %s" % st)
elif "<release>%s</release>" % EXPECT_RELEASE in meta:
    ok("C metadata", "release 仍是 %s" % EXPECT_RELEASE)
else:
    diff("C metadata", "release 不再是 %s" % EXPECT_RELEASE)

# ------------------------------------------------------------------ D
print()
print("=" * 78)
print("D 组 —— 仓库级 advisory 原文")
print("=" * 78)
st, repo = gh_status("repos/%s/security-advisories?per_page=100" % REPO)
if st != 200:
    dead("D", "查询出错:%s" % st)
else:
    (ok if len(repo) == EXPECT_REPO_TOTAL else diff)("D 条数", "%d 条(基线 %d)" % (len(repo), EXPECT_REPO_TOTAL))
    a = next((x for x in repo if x["ghsa_id"] == GLOBAL_POSITIVE), None)
    if a and QUOTE_85721 in (a.get("description") or ""):
        ok("D 原文", "CVE-2026-85721 原文仍写着 “%s”" % QUOTE_85721)
    else:
        diff("D 原文", "CVE-2026-85721 原文里找不到那句 —— README 引用要重核")

# ------------------------------------------------------------------ 结论
print()
print("=" * 78)
if broken:
    print("☠️ 探针本身坏了 %d 项,读数作废(不是「信息差没变」):" % len(broken))
    for b in broken:
        print("   · %s" % b)
if changed:
    print("❌ 信息差已变,文案要改(%d 项):" % len(changed))
    for c in changed:
        print("   · %s" % c)
    sys.exit(1)
if broken:
    sys.exit(2)
print("✅ 信息差仍在:全局库仍缺 13 条、OSV 对 3.0.12 仍为空、Central 状态不变、原文不变。")
