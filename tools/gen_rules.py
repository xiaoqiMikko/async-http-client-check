#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 AsyncHttpClient 的**仓库级** security advisory 生成 RuleTable.java。

为什么是仓库级:2026-08-09 官方仓库一次发了 17 条 advisory,而 GitHub **全局** advisory 库
(Dependabot / OSV 读的那个)到 2026-09-19 只收了其中 4 条,另外 13 条 `advisories/<GHSA>` 直接 404。
全局库看不见的东西,只能从 `repos/AsyncHttpClient/async-http-client/security-advisories` 拿。
⚠️ 仓库级的键名与全局库不同:修复版是 `patched_versions`,不是 `first_patched_version`
   (与 jetty-line-check/tools/gen_table.py 的回退逻辑同一个坑)。

🔴 规则表不许手抄 —— 第 6 注实证:手抄会让一条 CVE 挂上另一条的标题,而断言、测试、真 jar 复验全部通过。

🔴 七条断言,任一不过就拒绝出表(宁可不生成,也不生成一张看起来对的错表):
   ASSERT1  仓库级条数 = 基线 21(其中 2026-08-09 那批 17 条),全部 published,
            每条都有本包条目,patched_versions 是单值
   ASSERT2  ⭐ 全局库缺失集合 = 基线那 13 条 GHSA(一条不多一条不少)。
            变了 = 信息差本身变了 —— 停下来,先更新结论再生成
   ASSERT3  交集修复版:3.x = 3.0.13,2.x = 2.16.1;
            且「只按全局库算」的 3.x 交集 = 3.0.12(那正是 Dependabot 会叫你升的版本)
   ASSERT4  Central 阳性(3.0.13 / 2.16.1 / 3.0.12 为 200)+ 哨兵(3.0.999 为 404)
   ASSERT5  ⭐ 承重墙:3.0.12 在本表下**必须**命中 >= 1 条 high,且这些 high 全部是全局库未收录
   ASSERT6  区间算子多种写法都在(>=、<=、<、显式 =、裸版本号),并有边界用例证明没被统一:
            3.0.11 对 `< 3.0.11`(CVE-2026-55688)判安全、对 `<= 3.0.11`(GHSA-v9f2)判中招;
            3.0.12 对 `= 3.0.12`(GHSA-qhv6)判中招、3.0.11 / 3.0.13 判安全
   ASSERT7  仓库级与全局库对同一条 advisory 的区间/严重度分歧 = 基线(只有 CVE-2024-53990 一处)。
            两边都收的条目,规则取**并集**(宁可多报不许漏报),分歧变了就停下

用法:  python tools/gen_rules.py [--dry]
       --dry 只跑断言并打印,不写文件。
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = "AsyncHttpClient/async-http-client"
PKG = "org.asynchttpclient:async-http-client"

# GHSA → 中文标题。2026-09-19 从仓库级 advisory 的 summary 逐条译出核过。
TITLES = {
    "GHSA-vvp4-63h8-v5pm": "连接池 key 不含认证主体 -> NTLM/Negotiate 连接跨身份复用",
    "GHSA-f9m8-cv68-674w": "Cookie Domain 不查公共后缀表 -> 可对 co.uk 种 cookie",
    "GHSA-qhv6-3pmh-95q4": "对端给 qop=auth-int 即关掉 Digest 双向认证",
    "GHSA-jmqq-x5g9-9p2w": "重放到另一主机时把原主机的请求与凭据发给新主机",
    "GHSA-rqf5-2wxv-rjf4": "Digest 质询缺可用 nonce -> 降级 Basic,明文发送密码",
    "GHSA-v9f2-7rw2-gr2x": "代理拒绝 CONNECT 时,源站凭据明文发给代理",
    "GHSA-mfj3-87qq-382v": "Digest cnonce 用非密码学随机源生成",
    "GHSA-rwhr-j9rv-85f8": "WebSocket 握手 Sec-WebSocket-Accept 校验失败后仍继续",
    "GHSA-3wp9-xfwm-rjjf": "WebSocket 走 CONNECT 隧道时代理凭据发给源站",
    "GHSA-cf59-3jcr-vfhw": "断点续传索引文件全局可读且跟随预置符号链接",
    "GHSA-qpfv-56x8-xgx4": "URL userinfo 凭据写进发给 HTTP 代理的请求行",
    "GHSA-fj9w-c36g-h5x8": "SCRAM/Digest 双向认证响应未校验",
    "GHSA-gcmv-gr82-6m8v": "TLS 握手失败泄漏连接许可 -> 按主机拒绝服务",
    "GHSA-f8m2-889x-vw4x": "客户端级 realm 凭据在跨源重定向时被重发",
    "GHSA-x5w6-vm3f-pp6f": "SOCKS 代理凭据经明文 HTTP 发给源站",
    "GHSA-xr57-gcx8-52hf": "明文 CONNECT 请求把源站凭据发给代理",
    "GHSA-7grg-jcf7-rpmx": "HTTP/1.1 响应解压无上限 -> 解压炸弹拒绝服务",
    "GHSA-m452-q8c9-rg2f": "ThreadSafeCookieStore 为无关域存 cookie(cookie tossing)",
    "GHSA-fmxf-pm6p-7xgm": "跨源重定向不剥离 Cookie 头",
    "GHSA-cmxv-58fp-fm3g": "跨源重定向把 Authorization 凭据泄给不可信域",
    "GHSA-mfj5-cf8g-g2fv": "CookieStore 覆盖显式设置的 Cookie",
}

# ---- ASSERT1 基线(2026-09-19 实测)
EXPECT_TOTAL = 21
BATCH_DATE = "2026-08-09"
EXPECT_BATCH = 17

# ---- ⭐ ASSERT2 基线:全局库 404 的 13 条(2026-09-19 实测,逐条 `gh api advisories/<GHSA>`)
EXPECT_MISSING = {
    "GHSA-vvp4-63h8-v5pm", "GHSA-f9m8-cv68-674w", "GHSA-qhv6-3pmh-95q4", "GHSA-jmqq-x5g9-9p2w",
    "GHSA-rqf5-2wxv-rjf4", "GHSA-v9f2-7rw2-gr2x", "GHSA-mfj3-87qq-382v", "GHSA-rwhr-j9rv-85f8",
    "GHSA-3wp9-xfwm-rjjf", "GHSA-cf59-3jcr-vfhw", "GHSA-qpfv-56x8-xgx4", "GHSA-gcmv-gr82-6m8v",
    "GHSA-x5w6-vm3f-pp6f",
}

# ---- ASSERT3
EXPECT_FIX = {"3.x": "3.0.13", "2.x": "2.16.1"}
EXPECT_DEPENDABOT_FIX_3X = "3.0.12"

# ---- ASSERT4
CENTRAL_POSITIVE = ["3.0.13", "2.16.1", "3.0.12"]
SENTINEL = "3.0.999"

# ---- ⭐ ASSERT5
LOADBEARING_VERSION = "3.0.12"

# ---- ASSERT6 边界用例
BOUNDARY = [
    # (版本, GHSA, 预期是否命中, 说明)
    ("3.0.11", "GHSA-m452-q8c9-rg2f", False, "`< 3.0.11` 严格小于"),
    ("3.0.11", "GHSA-v9f2-7rw2-gr2x", True, "`<= 3.0.11` 含等号"),
    ("3.0.12", "GHSA-qhv6-3pmh-95q4", True, "`= 3.0.12` 显式等号"),
    ("3.0.11", "GHSA-qhv6-3pmh-95q4", False, "`= 3.0.12` 显式等号"),
    ("3.0.13", "GHSA-qhv6-3pmh-95q4", False, "`= 3.0.12` 显式等号"),
    ("3.0.12", "GHSA-rqf5-2wxv-rjf4", True, "`<= 3.0.12` 含等号"),
]
EXPECT_OPS = {">=", "<=", "<", "=", "bare"}

# ---- ASSERT7 基线:仓库级与全局库的分歧(2026-09-19 实测)
#   CVE-2024-53990:仓库级只写 3.x 线裸版本 `3.0.0`;全局库写 `>= 3.0.0.Beta1, < 3.0.1` 与
#   2.x 线 `>= 2.1.0, < 2.12.4`。**只信仓库级会把 2.1.0~2.12.3 漏掉** —— 所以取并集。
EXPECT_DIVERGE = {
    ("GHSA-mfj5-cf8g-g2fv", "2.x"): ((), (">= 2.1.0, < 2.12.4",)),
    ("GHSA-mfj5-cf8g-g2fv", "3.x"): (("3.0.0",), (">= 3.0.0.Beta1, < 3.0.1",)),
}

VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[.\-](.+))?$")
STAGE_RE = re.compile(r"^(ALPHA|BETA|M|RC|CR)0*(\d*)$")
STAGE_W = {"ALPHA": 1, "BETA": 2, "M": 3, "RC": 4, "CR": 4}


def vkey(v):
    """与 Versions.java 同一套规则:预发布排在同号正式版之前。解析不了直接退出,不许当 0。"""
    m = VER_RE.match(v.strip())
    if not m:
        sys.exit("[FATAL] 解析不了的版本号 %r" % v)
    base = [int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)]
    suf = (m.group(4) or "").upper()
    if suf in ("", "FINAL", "RELEASE", "GA"):
        return base + [5, 0]
    s = STAGE_RE.match(suf)
    if not s:
        sys.exit("[FATAL] 认不出的版本后缀 %r" % v)
    return base + [STAGE_W[s.group(1)], int(s.group(2) or 0)]


def line_of(v):
    m = VER_RE.match(v.strip())
    return ("%s.x" % m.group(1)) if m else None


PART_RE = re.compile(r"^\s*(>=|>|<=|<|=)?\s*(\d[\w.\-]*?)\s*$")


def parse_range(rng):
    """→ [(op, bound)];op 为 None 表示裸版本号(= 精确等于)。认不出直接退出。"""
    if not rng or not rng.strip():
        sys.exit("[FATAL] 空区间 —— 不许当「不受影响」")
    out = []
    for part in rng.split(","):
        m = PART_RE.match(part)
        if not m:
            sys.exit("[FATAL] 认不出的区间片段: %r(整段 %r)—— 不许当「不受影响」" % (part, rng))
        out.append((m.group(1), m.group(2)))
    return out


def in_range(rng, v):
    """🔴 逐条按原文算子判,不统一。"""
    for op, bound in parse_range(rng):
        a, b = vkey(v), vkey(bound)
        c = (a > b) - (a < b)
        ok = {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0, "=": c == 0, None: c == 0}[op]
        if not ok:
            return False
    return True


def range_line(rng):
    """一个区间属于哪条版本线:取区间里所有界的主版本,必须唯一。"""
    lines = {line_of(b) for _op, b in parse_range(rng)}
    if len(lines) != 1:
        sys.exit("[FATAL] 区间 %r 跨了多条版本线 %s,口径变了" % (rng, sorted(lines)))
    return lines.pop()


def gh(path, allow_404=False):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        if allow_404 and "HTTP 404" in (out.stderr or ""):
            return None
        sys.exit("[FATAL] gh api %s 失败:%s" % (path, out.stderr.strip()))
    return json.loads(out.stdout)


def central(version):
    url = ("https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/%s/"
           "async-http-client-%s.jar" % (version, version))
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    dry = "--dry" in sys.argv

    repo = gh("repos/%s/security-advisories?per_page=100" % REPO)

    # ---- ASSERT1
    if len(repo) != EXPECT_TOTAL:
        sys.exit("[ASSERT1 FAIL] 仓库级 advisory %d 条,基线 %d —— 上游动了,先更新结论再生成"
                 % (len(repo), EXPECT_TOTAL))
    batch = [a for a in repo if (a.get("published_at") or "").startswith(BATCH_DATE)]
    if len(batch) != EXPECT_BATCH:
        sys.exit("[ASSERT1 FAIL] %s 那批 %d 条,基线 %d" % (BATCH_DATE, len(batch), EXPECT_BATCH))
    for a in repo:
        if a.get("state") != "published":
            sys.exit("[ASSERT1 FAIL] %s state=%s" % (a["ghsa_id"], a.get("state")))
        if a.get("withdrawn_at"):
            sys.exit("[ASSERT1 FAIL] %s 已撤回(withdrawn_at=%s)" % (a["ghsa_id"], a["withdrawn_at"]))
        if a["ghsa_id"] not in TITLES:
            sys.exit("[ASSERT1 FAIL] %s 没有中文标题 —— 新出现的条目,先读原文再补" % a["ghsa_id"])
    print("✅ ASSERT1:仓库级 %d 条(%s 那批 %d 条),全部 published、未撤回"
          % (len(repo), BATCH_DATE, len(batch)))

    rows = []
    missing = set()
    diverge = {}
    for a in repo:
        ghsa = a["ghsa_id"]
        repo_by_line = {}
        for v in a.get("vulnerabilities") or []:
            if v.get("package", {}).get("name") != PKG:
                continue
            rng, pv = v.get("vulnerable_version_range"), v.get("patched_versions")
            if not pv or "," in pv:
                sys.exit("[ASSERT1 FAIL] %s patched_versions=%r,不是单值" % (ghsa, pv))
            ln = range_line(rng)
            if line_of(pv) != ln:
                sys.exit("[ASSERT1 FAIL] %s 区间 %r 与修复版 %s 不在同一条线" % (ghsa, rng, pv))
            repo_by_line.setdefault(ln, []).append((rng, pv))
        if not repo_by_line:
            sys.exit("[ASSERT1 FAIL] %s 没有 %s 条目" % (ghsa, PKG))

        g = gh("advisories/" + ghsa, allow_404=True)
        glob_by_line = {}
        if g is None:
            missing.add(ghsa)
        else:
            if g.get("type") != "reviewed" or g.get("withdrawn_at"):
                sys.exit("[ASSERT2 FAIL] %s 全局库 type=%s withdrawn=%s" % (ghsa, g.get("type"), g.get("withdrawn_at")))
            if (g.get("cve_id") or None) != (a.get("cve_id") or None):
                sys.exit("[ASSERT7 FAIL] %s 两边 cve_id 不一致:仓库级 %s / 全局 %s"
                         % (ghsa, a.get("cve_id"), g.get("cve_id")))
            if g.get("severity") != a.get("severity"):
                sys.exit("[ASSERT7 FAIL] %s 两边 severity 不一致:仓库级 %s / 全局 %s"
                         % (ghsa, a.get("severity"), g.get("severity")))
            for v in g.get("vulnerabilities") or []:
                if v.get("package", {}).get("name") != PKG:
                    continue
                rng, fp = v.get("vulnerable_version_range"), v.get("first_patched_version")
                if not fp:
                    sys.exit("[ASSERT7 FAIL] %s 全局库条目没有 first_patched_version" % ghsa)
                glob_by_line.setdefault(range_line(rng), []).append((rng, fp))

        for ln in sorted(set(repo_by_line) | set(glob_by_line)):
            r_rngs = tuple(sorted(x[0] for x in repo_by_line.get(ln, [])))
            g_rngs = tuple(sorted(x[0] for x in glob_by_line.get(ln, [])))
            if g is not None and r_rngs != g_rngs:
                diverge[(ghsa, ln)] = (r_rngs, g_rngs)
            # 并集:仓库级每条都进表;全局库里仓库级没有的区间也进表(宁可多报不许漏报)
            for rng, fix in repo_by_line.get(ln, []):
                rows.append(dict(ghsa=ghsa, cve=a.get("cve_id"), severity=a["severity"], line=ln,
                                 range=rng, fix=fix, in_global=g is not None, source="仓库级"))
            for rng, fix in glob_by_line.get(ln, []):
                if rng not in r_rngs:
                    rows.append(dict(ghsa=ghsa, cve=a.get("cve_id"), severity=a["severity"], line=ln,
                                     range=rng, fix=fix, in_global=True, source="全局库"))

    # ---- ⭐ ASSERT2
    if missing != EXPECT_MISSING:
        sys.exit("[ASSERT2 FAIL] 全局库缺失集合变了 —— 信息差本身变了,**先更新结论与文案再生成**\n"
                 "  新收录(基线缺、现在有):%s\n  新缺失(基线有、现在缺):%s"
                 % (sorted(EXPECT_MISSING - missing) or "无", sorted(missing - EXPECT_MISSING) or "无"))
    print("✅ ASSERT2:全局库缺 %d 条(与基线一致),收录 %d 条"
          % (len(missing), len(repo) - len(missing)))

    # ---- ASSERT3
    for ln, expect in EXPECT_FIX.items():
        got = max((r["fix"] for r in rows if r["line"] == ln), key=vkey)
        if got != expect:
            sys.exit("[ASSERT3 FAIL] %s 线交集 %s,预期 %s —— 上游动了,先更新结论再生成" % (ln, got, expect))
    dep3 = max((r["fix"] for r in rows if r["line"] == "3.x" and r["in_global"]), key=vkey)
    if dep3 != EXPECT_DEPENDABOT_FIX_3X:
        sys.exit("[ASSERT3 FAIL] 只按全局库算,3.x 交集是 %s,预期 %s —— 「Dependabot 叫你升 3.0.12」这句不成立了"
                 % (dep3, EXPECT_DEPENDABOT_FIX_3X))
    print("✅ ASSERT3:交集 3.x = %s / 2.x = %s;只按全局库算 3.x = %s"
          % (EXPECT_FIX["3.x"], EXPECT_FIX["2.x"], dep3))

    # ---- ASSERT4
    for v in CENTRAL_POSITIVE:
        st = central(v)
        if st != 200:
            sys.exit("[ASSERT4 FAIL] %s 在 Central 上是 %s,不是 200" % (v, st))
    st = central(SENTINEL)
    if st != 404:
        sys.exit("[ASSERT4 FAIL] 哨兵 %s 是 %s 不是 404 —— 探测方式本身坏了,读数作废" % (SENTINEL, st))
    print("✅ ASSERT4:Central %s 均 200;哨兵 %s 为 404" % (" / ".join(CENTRAL_POSITIVE), SENTINEL))

    # ---- ⭐ ASSERT5
    hits = {}
    for r in rows:
        if r["line"] == line_of(LOADBEARING_VERSION) and in_range(r["range"], LOADBEARING_VERSION):
            hits.setdefault(r["ghsa"], r)
    highs = [r for r in hits.values() if r["severity"] in ("high", "critical")]
    if not highs:
        sys.exit("[ASSERT5 FAIL] %s 在本表下没有命中任何 high —— 本注承重墙塌了,停下来重新定位"
                 % LOADBEARING_VERSION)
    seen = [r["ghsa"] for r in highs if r["in_global"]]
    if seen:
        sys.exit("[ASSERT5 FAIL] %s 命中的 high 里 %s 已被全局库收录 —— 「Dependabot 看不见」不成立了"
                 % (LOADBEARING_VERSION, seen))
    print("✅ ASSERT5:%s 在本表下命中 %d 条(%s),其中 high %d 条(%s)全部全局库未收录"
          % (LOADBEARING_VERSION, len(hits), ", ".join(sorted(hits)),
             len(highs), ", ".join(sorted(r["ghsa"] for r in highs))))

    # ---- ASSERT6
    ops = set()
    for r in rows:
        for op, _b in parse_range(r["range"]):
            ops.add(op if op else "bare")
    if not EXPECT_OPS <= ops:
        sys.exit("[ASSERT6 FAIL] 算子写法只出现 %s,预期至少 %s —— 上游改写法了,边界用例要重挑"
                 % (sorted(ops), sorted(EXPECT_OPS)))
    for ver, ghsa, expect, why in BOUNDARY:
        rs = [r for r in rows if r["ghsa"] == ghsa and r["line"] == line_of(ver)]
        if not rs:
            sys.exit("[ASSERT6 FAIL] %s 在 %s 线没有规则" % (ghsa, line_of(ver)))
        got = any(in_range(r["range"], ver) for r in rs)
        if got != expect:
            sys.exit("[ASSERT6 FAIL] %s 对 %s(%s)应判%s,实际判%s"
                     % (ver, ghsa, why, "中招" if expect else "安全", "中招" if got else "安全"))
    print("✅ ASSERT6:算子写法 %s 都在;%d 个边界用例判定正确(3.0.11 对 `<` 安全、对 `<=` 中招)"
          % (sorted(ops), len(BOUNDARY)))

    # ---- ASSERT7
    if diverge != EXPECT_DIVERGE:
        sys.exit("[ASSERT7 FAIL] 仓库级与全局库的区间分歧变了\n  现在:%s\n  基线:%s"
                 % (diverge, EXPECT_DIVERGE))
    print("✅ ASSERT7:仓库级/全局库区间分歧 %d 处,与基线一致(CVE-2024-53990,已取并集)" % len(diverge))

    print("✅ 七条断言全过。规则 %d 条(advisory %d 条)。" % (len(rows), len(repo)))

    java = render(rows)
    if dry:
        print("\n--dry:不写文件。")
        return
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "..", "src", "main", "java", "dev", "mikko", "ahccheck", "RuleTable.java")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(java)
    print("→ 已写 %s" % os.path.normpath(out))


def render(rows):
    def j(s):
        return "null" if s is None else '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = sorted(rows, key=lambda r: (r["line"], order.get(r["severity"], 9), r["ghsa"], r["range"]))
    body = ["        add(%s, %s, %s, %s, %s, %s, %s, %s, %s);"
            % (j(r["ghsa"]), j(r["cve"]), j(TITLES[r["ghsa"]]), j(r["severity"]), j(r["line"]),
               j(r["range"]), j(r["fix"]), "true" if r["in_global"] else "false", j(r["source"]))
            for r in rows]

    header = """package dev.mikko.ahccheck;

import java.util.ArrayList;
import java.util.List;

/**
 * 规则表 —— <b>本文件由 tools/gen_rules.py 生成,不要手改。</b>
 *
 * <p>来源是 AsyncHttpClient 的<b>仓库级</b> security advisory(21 条),不是 GitHub 全局 advisory 库 ——
 * 全局库(Dependabot / OSV 读的那个)到 2026-09-19 只收了其中 8 条,2026-08-09 那批 17 条里缺 13 条。
 * {@code inGlobal} 字段记的就是「Dependabot 看不看得见这一条」。
 *
 * <p>🔴 区间算子混用 {@code >=} / {@code <=} / {@code <} / {@code =} / 裸版本号,<b>逐条按原文判,不许统一</b>。
 * 同一个 3.0.11:对 CVE-2026-55688({@code < 3.0.11})是安全,对 GHSA-v9f2({@code <= 3.0.11})是中招 ——
 * 由 gen_rules 的 ASSERT6 守着。
 *
 * <p>🔴 仓库级与全局库都收的条目,规则取<b>并集</b>:CVE-2024-53990 仓库级只写了 3.x 线的 {@code 3.0.0},
 * 全局库还写了 2.x 线 {@code >= 2.1.0, < 2.12.4}。只信一边会漏报 —— 由 ASSERT7 守着。
 */
final class RuleTable {

    static final List<Rule> RULES = new ArrayList<>();

    /**
     * 一条 advisory 在一条版本线上的一个区间。
     *
     * @param inGlobal 这条 advisory 是否被 GitHub 全局 advisory 库收录(= Dependabot/OSV 看不看得见)
     * @param source   这个区间取自哪里:「仓库级」或「全局库」
     */
    record Rule(String ghsa, String cve, String title, String severity, String line,
                String range, String fix, boolean inGlobal, String source) {

        /** 展示用编号:有 CVE 用 CVE,没有用 GHSA。 */
        String id() { return cve != null ? cve : ghsa; }
    }

    private static void add(String ghsa, String cve, String title, String severity, String line,
                            String range, String fix, boolean inGlobal, String source) {
        RULES.add(new Rule(ghsa, cve, title, severity, line, range, fix, inGlobal, source));
    }

    static {
"""
    footer = """
    }

    private RuleTable() { }
}
"""
    return header + "\n".join(body) + footer


if __name__ == "__main__":
    main()
