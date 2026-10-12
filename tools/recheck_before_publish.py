#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""async-http-client-check —— 发布前事实复核(v0.2.0 口径,基线 2026-10-12)。

本工具对外说三件事,每一件都会随时间失效,**失效的那天文案就是错的**:
   ① 仓库级 26 条里,GitHub 全局 advisory 库(Dependabot / OSV 读的)仍缺 9 条;
   ② 3.x 的答案是 3.0.14;
   ③ 2.x 线已停止维护:终版 2.16.1 仍中 5 条,这 5 条在 2.x 上没有修复版。
发任何东西之前跑一遍;任一项变了就打印「口径已变,文案要改」并非零退出。

☠️ 由来:v0.1.0(2026-09-20 发)的三句话「全局库只收 4 条 / Dependabot 叫你升 3.0.12 / 答案 3.0.13」
   在 09-24 与 10-08 两次上游变化后全部过时,10-10 才被这个脚本撞见 —— 它当时没挂进每日复查。

🔴 每一组都带阳性对照或哨兵 —— 单向判据和没验证长得一模一样:
   · 全局库 404 可能是「真没收」,也可能是 gh 没登录 / 限流 —— 所以同时查一条**必定已收录**的(阳性)
     和一条**必定不存在**的(哨兵)。
   · OSV 返回空可能是「真没有」,也可能是包名/生态拼错 —— 所以同时查 3.0.13(必定非空)。
   · Central 404 可能是「真没有」,也可能是网络挡了 —— 所以同时查必定存在的版本。

四组:
   A  全局 advisory 库仍缺那 9 条(逐条 + 按包列表两种查法);按包列表里本批已收录的条数 = 26 - 9
   B  ⭐ 独立口径(OSV,不复用生成脚本读的 GitHub advisory 区间):
      3.0.14 零漏洞 · 3.0.13 非空 · 2.16.1 非空 · 那 9 条按编号仍查不到
   C  Central:3.0.14 / 3.0.13 / 2.16.1 为 200,3.0.15 与 2.16.2 仍 404,release 仍是 3.0.14,
      2.x 线没有比 2.16.1 更新的版本
   D  仓库级原文:仍是 26 条;那 5 条的 2.x 修复版仍为空,且原文仍写着 2.x 停止维护那一句

退出码:0 = 口径仍成立,文案可用;1 = 口径已变,文案要改;2 = 探针本身坏了(读数作废)。

用法:  python -u tools/recheck_before_publish.py
"""
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG = "org.asynchttpclient:async-http-client"
REPO = "AsyncHttpClient/async-http-client"

MISSING_9 = [
    "GHSA-vvp4-63h8-v5pm", "GHSA-qhv6-3pmh-95q4", "GHSA-v9f2-7rw2-gr2x", "GHSA-rwhr-j9rv-85f8",
    "GHSA-cf59-3jcr-vfhw", "GHSA-qpfv-56x8-xgx4", "GHSA-gcmv-gr82-6m8v", "GHSA-x5w6-vm3f-pp6f",
    "GHSA-qjr7-w8pj-pmv9",
]
UNFIXED_2X = [
    "GHSA-v2j5-22fr-j62r", "GHSA-qjr7-w8pj-pmv9", "GHSA-x8v2-478q-2hvg",
    "GHSA-p2jm-6hj6-9rjg", "GHSA-2jwh-9rmr-j4xf",
]
GLOBAL_POSITIVE = "GHSA-7grg-jcf7-rpmx"        # CVE-2026-85721,09-17 已被全局库收录
GLOBAL_SENTINEL = "GHSA-zzzz-zzzz-zzzz"        # 不存在的编号

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"

CENTRAL = "https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/%s/async-http-client-%s.jar"
CENTRAL_META = "https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/maven-metadata.xml"
EXPECT_200 = ["3.0.14", "3.0.13", "2.16.1"]
EXPECT_404 = {"3.0.15": "3.x 出了新版本 —— 「3.0.14 是答案」要重新核",
              "2.16.2": "2.x 出了新版本 —— 「2.x 不再修」要重新核"}
EXPECT_RELEASE = "3.0.14"
LAST_2X = "2.16.1"

EXPECT_REPO_TOTAL = 26
EOL_QUOTE = "The 2.x line is end of life and will not receive a fix"

changed = []   # 口径变了 → 文案要改
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
    """→ (状态, json 或 None)。状态 200 / 404 / 'ERR'。
    🔴 只重试「没拿到 HTTP 状态」的失败(连接被重置);拿到 404 就是 404,不许重试成别的结论。"""
    for _attempt in range(4):
        r = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
        if r.returncode == 0:
            return 200, json.loads(r.stdout)
        if "HTTP 404" in (r.stderr or ""):
            return 404, None
        if "HTTP " in (r.stderr or ""):
            break
        time.sleep(2)
    return "ERR:" + (r.stderr or "").strip()[:120], None


def http(url, data=None, method=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "ahc-check-recheck", "Content-Type": "application/json"})
    last = None
    for _attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception as e:      # 连接类错误才重试
            last = e
            time.sleep(2)
    return "ERR:%s" % last, ""


def osv_query(version):
    body = json.dumps({"package": {"name": PKG, "ecosystem": "Maven"}, "version": version}).encode()
    st, txt = http(OSV_QUERY, data=body, method="POST")
    if st != 200:
        return None
    return [v["id"] for v in json.loads(txt or "{}").get("vulns", [])]


def vkey(v):
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", v)
    return tuple(int(x or 0) for x in m.groups()) if m else (0, 0, 0)


# ------------------------------------------------------------------ D(先拉仓库级,A 组要用它的编号全集)
st_repo, repo = gh_status("repos/%s/security-advisories?per_page=100" % REPO)

# ------------------------------------------------------------------ A
print("=" * 78)
print("A 组 —— GitHub 全局 advisory 库(Dependabot 读的)是否仍缺那 9 条")
print("=" * 78)
st, _ = gh_status("advisories/" + GLOBAL_POSITIVE)
(ok if st == 200 else dead)("A 阳性", "%s → %s(应 200)" % (GLOBAL_POSITIVE, st))
st, _ = gh_status("advisories/" + GLOBAL_SENTINEL)
(ok if st == 404 else dead)("A 哨兵", "%s → %s(应 404)" % (GLOBAL_SENTINEL, st))
now_in = []
for g in MISSING_9:
    st, _ = gh_status("advisories/" + g)
    if st == 200:
        now_in.append(g)
    elif st != 404:
        dead("A %s" % g, "查询出错:%s" % st)
if now_in:
    diff("A 收录", "全局库新收录了 %d 条:%s —— 「仍缺 9 条」要改" % (len(now_in), ", ".join(now_in)))
else:
    ok("A 收录", "9 条全局库仍然全部 404")
st, lst = gh_status("advisories?ecosystem=maven&affects=%s&per_page=100" % PKG)
if st != 200:
    dead("A 按包查", "查询出错:%s" % st)
elif st_repo != 200:
    dead("A 按包查", "仓库级列表没拉到(%s),没法对数" % st_repo)
else:
    listed = {a["ghsa_id"] for a in lst}
    hit = sorted(listed & set(MISSING_9))
    (diff if hit else ok)("A 按包查", "按包列出的条目里含那 9 条中的:%s" % (hit or "无"))
    # ⭐ 用另一个口径把同一批东西数一遍:按包列表 ∩ 仓库级全集,应恰好 = 26 - 9
    both = listed & {a["ghsa_id"] for a in repo}
    want = EXPECT_REPO_TOTAL - len(MISSING_9)
    (ok if len(both) == want else diff)("A 对数", "按包列表里属于仓库级那批的有 %d 条(应 %d = %d - %d)"
                                       % (len(both), want, EXPECT_REPO_TOTAL, len(MISSING_9)))

# ------------------------------------------------------------------ B
print()
print("=" * 78)
print("B 组 —— 独立口径 OSV:3.0.14 干净 / 3.0.13 与 2.16.1 不干净")
print("=" * 78)
v13 = osv_query("3.0.13")
if not v13:
    dead("B 阳性", "OSV 对 3.0.13 返回 %s —— 应非空,查询方式本身坏了,本组读数作废" % v13)
else:
    ok("B 阳性", "OSV 对 3.0.13 返回 %d 条(%s)" % (len(v13), ", ".join(sorted(v13))))
v14 = osv_query("3.0.14")
if v14 is None:
    dead("B 3.0.14", "OSV 查询出错")
elif v14:
    diff("B 3.0.14", "OSV 对 3.0.14 现在返回 %d 条:%s —— 「3.0.14 是答案」要重新核" % (len(v14), ", ".join(sorted(v14))))
else:
    ok("B 3.0.14", "OSV 对 3.0.14 返回零漏洞")
v2 = osv_query(LAST_2X)
if v2 is None:
    dead("B %s" % LAST_2X, "OSV 查询出错")
elif not v2:
    diff("B %s" % LAST_2X, "OSV 对 %s 返回零漏洞 —— 与「2.x 终版仍中 5 条」对不上,要重新核" % LAST_2X)
else:
    ok("B %s" % LAST_2X, "OSV 对 %s 返回 %d 条(%s)" % (LAST_2X, len(v2), ", ".join(sorted(v2))))
st, _ = http(OSV_VULN % GLOBAL_POSITIVE)
(ok if st == 200 else dead)("B 按编号阳性", "OSV %s → %s(应 200)" % (GLOBAL_POSITIVE, st))
now_osv = []
for g in MISSING_9:
    st, _ = http(OSV_VULN % g)
    if st == 200:
        now_osv.append(g)
    elif st != 404:
        dead("B %s" % g, "OSV 查询出错:%s" % st)
(diff if now_osv else ok)("B 按编号", "OSV 按编号查得到的:%s" % (now_osv or "无(9 条仍全部 404)"))

# ------------------------------------------------------------------ C
print()
print("=" * 78)
print("C 组 —— Maven Central 状态")
print("=" * 78)
for v in EXPECT_200:
    st, _ = http(CENTRAL % (v, v), method="HEAD")
    (ok if st == 200 else (dead if str(st).startswith("ERR") else diff))("C %s" % v, "HTTP %s(应 200)" % st)
for v, why in EXPECT_404.items():
    st, _ = http(CENTRAL % (v, v), method="HEAD")
    if st == 404:
        ok("C %s" % v, "HTTP 404(还没发)")
    elif st == 200:
        diff("C %s" % v, "%s 已经发布 —— %s" % (v, why))
    else:
        dead("C %s" % v, "HTTP %s" % st)
st, meta = http(CENTRAL_META)
if st != 200:
    dead("C metadata", "HTTP %s" % st)
else:
    if "<release>%s</release>" % EXPECT_RELEASE in meta:
        ok("C metadata", "release 仍是 %s" % EXPECT_RELEASE)
    else:
        diff("C metadata", "release 不再是 %s" % EXPECT_RELEASE)
    versions = re.findall(r"<version>([^<]+)</version>", meta)
    if LAST_2X not in versions:
        dead("C 2.x", "版本表里没有 %s —— 版本表读数不可信" % LAST_2X)
    else:
        newer = [v for v in versions if v.startswith("2.") and vkey(v) > vkey(LAST_2X)]
        (diff if newer else ok)("C 2.x", "2.x 线比 %s 更新的版本:%s" % (LAST_2X, newer or "无"))

# ------------------------------------------------------------------ D
print()
print("=" * 78)
print("D 组 —— 仓库级 advisory 原文")
print("=" * 78)
if st_repo != 200:
    dead("D", "查询出错:%s" % st_repo)
else:
    (ok if len(repo) == EXPECT_REPO_TOTAL else diff)("D 条数", "%d 条(基线 %d)" % (len(repo), EXPECT_REPO_TOTAL))
    by = {a["ghsa_id"]: a for a in repo}
    for g in UNFIXED_2X:
        a = by.get(g)
        if a is None:
            diff("D %s" % g, "仓库级列表里找不到这一条")
            continue
        rows2 = [v for v in a.get("vulnerabilities") or []
                 if (v.get("vulnerable_version_range") or "").lstrip(">= ").startswith("2.")]
        if not rows2:
            diff("D %s" % g, "没有 2.x 区间了 —— 「2.x 仍中」要重新核")
            continue
        patched = [str(v.get("patched_versions") or "").strip() for v in rows2]
        if any(p and p != "None" for p in patched):
            diff("D %s" % g, "2.x 出现了修复版 %s —— 「2.x 无修复版」不成立了" % patched)
        elif EOL_QUOTE not in (a.get("description") or ""):
            diff("D %s" % g, "原文里找不到 “%s”" % EOL_QUOTE)
        else:
            ok("D %s" % g[:14], "2.x 区间 %s 仍无修复版,原文仍写着停止维护那句"
               % [v["vulnerable_version_range"] for v in rows2])

# ------------------------------------------------------------------ 结论
print()
print("=" * 78)
if broken:
    print("☠️ 探针本身坏了 %d 项,读数作废(不是「口径没变」):" % len(broken))
    for b in broken:
        print("   · %s" % b)
if changed:
    print("❌ 口径已变,文案要改(%d 项):" % len(changed))
    for c in changed:
        print("   · %s" % c)
    sys.exit(1)
if broken:
    sys.exit(2)
print("✅ 口径仍成立:全局库仍缺 9 条、3.0.14 干净、2.x 终版 2.16.1 仍中 5 条且无修复版、Central 状态不变。")
