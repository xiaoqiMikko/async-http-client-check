#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 AsyncHttpClient 的**仓库级** security advisory 生成 RuleTable.java。

为什么是仓库级:官方仓库 2026-08-09 一次发了 17 条、2026-09-24 又发 5 条,而 GitHub **全局** advisory 库
(Dependabot / OSV 读的那个)收得又慢又不全 —— 2026-09-19 时 08-09 那批只收了 4 条;
2026-10-12 复核时 26 条里仍有 9 条 `advisories/<GHSA>` 直接 404。
全局库看不见的东西,只能从 `repos/AsyncHttpClient/async-http-client/security-advisories` 拿。

🔴 2026-10-12(v0.2.0)口径变化,别照 v0.1.0 的印象读:
   · 3.x 的答案从 3.0.13 变成 **3.0.14**(09-24 那 5 条);
   · **2.x 线没有答案了** —— 09-24 那 5 条在 2.x 上 `patched_versions` 为空,原文逐条写着
     "The 2.x line is end of life and will not receive a fix."。修复版为空 = 「本线无修复版」,
     不是「不受影响」,也不是脏数据;
   · 「Dependabot 叫你升 3.0.12」那条卖点已失效(全局库 10-08 补收了一批),由 ASSERT3 记着。
⚠️ 仓库级的键名与全局库不同:修复版是 `patched_versions`,不是 `first_patched_version`
   (与 jetty-line-check/tools/gen_table.py 的回退逻辑同一个坑)。

🔴 规则表不许手抄 —— 第 6 注实证:手抄会让一条 CVE 挂上另一条的标题,而断言、测试、真 jar 复验全部通过。

🔴 七条断言,任一不过就拒绝出表(宁可不生成,也不生成一张看起来对的错表):
   ASSERT1  仓库级条数 = 基线 26(2026-08-09 那批 17 条 + 2026-09-24 那批 5 条),全部 published,
            每条都有本包条目;patched_versions 是单值,**为空时原文必须有 EOL 那句**(否则就是脏数据)
   ASSERT2  ⭐ 全局库缺失集合 = 基线那 9 条 GHSA(一条不多一条不少)。
            变了 = 信息差本身变了 —— 停下来,先更新结论再生成
   ASSERT3  3.x 交集修复版 = 3.0.14;2.x 线有修复的最高到 2.16.1,且**无修复版**的集合 = 基线那 5 条;
            「只按全局库算」的 3.x 交集也是 3.0.14(= Dependabot 现在给的数字是对的,旧卖点已失效)
   ASSERT4  Central 阳性(3.0.14 / 3.0.13 / 2.16.1 为 200)+ 哨兵(3.0.999 为 404)
            + 2.x 线没有比 2.16.1 更新的版本(读 maven-metadata.xml 全量版本表)
   ASSERT5  ⭐ 承重墙:2.x 终版 2.16.1 在本表下**必须**命中那 5 条无修复版的(其中 high 2 条);
            3.0.13 命中 5 条、全部 3.0.14 修;3.0.14 一条不中
   ASSERT6  区间算子多种写法都在(>=、<=、<、显式 =、裸版本号),并有边界用例证明没被统一:
            3.0.11 对 `< 3.0.11`(CVE-2026-55688)判安全、对 `<= 3.0.11`(GHSA-v9f2)判中招;
            3.0.12 对 `= 3.0.12`(GHSA-qhv6)判中招、3.0.11 / 3.0.13 判安全
   ASSERT7  仓库级与全局库对同一条 advisory 的区间/严重度分歧 = 基线
            (区间:CVE-2024-53990、CVE-2026-107230;严重度:CVE-2026-107282 官方 high / 全局库 critical)。
            两边都收的条目,规则取**并集**(宁可多报不许漏报),分歧变了就停下

用法:  python tools/gen_rules.py [--dry]
       --dry 只跑断言并打印,不写文件。
"""
import json
import os
import re
import subprocess
import sys
import time
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
    # 2026-09-24 那批 5 条,2026-10-12 逐条读过原文
    "GHSA-v2j5-22fr-j62r": "连接池仍会跨身份复用 NTLM/Negotiate/代理登录的连接(GHSA-vvp4 修复不完整)",
    "GHSA-qjr7-w8pj-pmv9": "默认 cookie 存储来源检查不完整 -> 可向公共后缀/IP 主机种 cookie",
    "GHSA-x8v2-478q-2hvg": "WebSocket permessage-deflate 解压无上限 -> 解压炸弹(要开 WebSocket 压缩,默认关)",
    "GHSA-p2jm-6hj6-9rjg": "明文 HTTP 收到的 cookie 可种入/覆盖/删除 HTTPS 的 Secure cookie",
    "GHSA-2jwh-9rmr-j4xf": "CookieStore 覆盖 setHeader 显式设置的 Cookie 头(CVE-2024-53990 修复被绕过)",
}

# 生成日 —— 写进规则表,工具运行时会把它印出来(「收录状态截至哪天」)。
# 🔴 重新生成时必须改成当天:v0.1.0 的教训是「未收录」这三个字印在 jar 里不会自己过期。
AS_OF = "2026-10-12"

# ---- ASSERT1 基线(2026-10-12 实测)
EXPECT_TOTAL = 26
EXPECT_BATCHES = {"2026-08-09": 17, "2026-09-24": 5}
# 修复版为空只在这一种情况下合法:原文写明该线停止维护。
EOL_LINE = "2.x"
EOL_QUOTE = "The 2.x line is end of life and will not receive a fix"

# ---- ⭐ ASSERT2 基线:全局库 404 的 9 条(2026-10-12 实测,逐条 `gh api advisories/<GHSA>`)
#   08-09 那批还缺 8 条 + 09-24 那批缺 1 条。09-19 时缺 13 条,10-08 全局库补收了其中 5 条。
EXPECT_MISSING = {
    "GHSA-vvp4-63h8-v5pm", "GHSA-qhv6-3pmh-95q4", "GHSA-v9f2-7rw2-gr2x", "GHSA-rwhr-j9rv-85f8",
    "GHSA-cf59-3jcr-vfhw", "GHSA-qpfv-56x8-xgx4", "GHSA-gcmv-gr82-6m8v", "GHSA-x5w6-vm3f-pp6f",
    "GHSA-qjr7-w8pj-pmv9",
}

# ---- ASSERT3
EXPECT_FIX_3X = "3.0.14"
EXPECT_LAST_FIX_2X = "2.16.1"
EXPECT_DEPENDABOT_FIX_3X = "3.0.14"
EXPECT_UNFIXED_2X = {
    "GHSA-v2j5-22fr-j62r", "GHSA-qjr7-w8pj-pmv9", "GHSA-x8v2-478q-2hvg",
    "GHSA-p2jm-6hj6-9rjg", "GHSA-2jwh-9rmr-j4xf",
}

# ---- ASSERT4
CENTRAL_POSITIVE = ["3.0.14", "3.0.13", "2.16.1"]
SENTINEL = "3.0.999"
CENTRAL_META = "https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/maven-metadata.xml"

# ---- ⭐ ASSERT5
LAST_2X = "2.16.1"
PREV_3X = "3.0.13"
CLEAN_3X = "3.0.14"

# ---- ASSERT6 边界用例
BOUNDARY = [
    # (版本, GHSA, 预期是否命中, 说明)
    ("3.0.11", "GHSA-m452-q8c9-rg2f", False, "`< 3.0.11` 严格小于"),
    ("3.0.11", "GHSA-v9f2-7rw2-gr2x", True, "`<= 3.0.11` 含等号"),
    ("3.0.12", "GHSA-qhv6-3pmh-95q4", True, "`= 3.0.12` 显式等号"),
    ("3.0.11", "GHSA-qhv6-3pmh-95q4", False, "`= 3.0.12` 显式等号"),
    ("3.0.13", "GHSA-qhv6-3pmh-95q4", False, "`= 3.0.12` 显式等号"),
    ("3.0.12", "GHSA-rqf5-2wxv-rjf4", True, "`<= 3.0.12` 含等号"),
    ("3.0.13", "GHSA-v2j5-22fr-j62r", True, "`<= 3.0.13` / `< 3.0.14` 两种写法都含 3.0.13"),
    ("3.0.14", "GHSA-v2j5-22fr-j62r", False, "`<= 3.0.13` / `< 3.0.14` 两种写法都不含 3.0.14"),
    ("2.16.1", "GHSA-x8v2-478q-2hvg", True, "`>= 2.2.0, <= 2.16.1` 含终版"),
    ("2.1.5", "GHSA-x8v2-478q-2hvg", False, "`>= 2.2.0` 下界"),
]
EXPECT_OPS = {">=", "<=", "<", "=", "bare"}

# ---- ASSERT7 基线:仓库级与全局库的分歧(2026-10-12 实测)
#   CVE-2024-53990:仓库级只写 3.x 线裸版本 `3.0.0`;全局库写 `>= 3.0.0.Beta1, < 3.0.1` 与
#   2.x 线 `>= 2.1.0, < 2.12.4`。**只信仓库级会把 2.1.0~2.12.3 漏掉** —— 所以取并集。
EXPECT_DIVERGE = {
    ("GHSA-mfj5-cf8g-g2fv", "2.x"): ((), (">= 2.1.0, < 2.12.4",)),
    ("GHSA-mfj5-cf8g-g2fv", "3.x"): (("3.0.0",), (">= 3.0.0.Beta1, < 3.0.1",)),
    # CVE-2026-107230:两边只是写法不同(`<= 3.0.13` 对 `< 3.0.14`),并集后判定不变
    ("GHSA-v2j5-22fr-j62r", "3.x"): ((">= 3.0.0, <= 3.0.13",), (">= 3.0.0, < 3.0.14",)),
}
# 严重度分歧:(仓库级, 全局库)。规则表**用仓库级的**(官方自评),分歧只记录不采纳。
EXPECT_SEV_DIVERGE = {
    "GHSA-jmqq-x5g9-9p2w": ("high", "critical"),
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
    # 连接被重置这类网络错误重试几次(2026-10-12 实测一轮 27 次调用会断 1 次);
    # 🔴 只重试「没拿到 HTTP 状态」的失败 —— 拿到状态码的(含 404)照原样往下判,不许重试成别的结论。
    for _attempt in range(4):
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
        if out.returncode == 0 or "HTTP " in (out.stderr or ""):
            break
        time.sleep(2)
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


def central_versions():
    """Central 上全部已发布版本(读 maven-metadata.xml)。读不到直接退出,不许当空表。"""
    try:
        with urllib.request.urlopen(CENTRAL_META, timeout=30) as r:
            xml = r.read().decode("utf-8", "replace")
    except Exception as e:
        sys.exit("[FATAL] 读 maven-metadata.xml 失败:%s" % e)
    vs = re.findall(r"<version>([^<]+)</version>", xml)
    if not vs:
        sys.exit("[FATAL] maven-metadata.xml 里一个 <version> 都没解析出来 —— 读数作废")
    return vs


def no_fix(pv):
    """修复版为空的三种写法(2026-10-12 实测同一批里就有 None / 空串 / 字面量 'None' 三种)。"""
    return pv is None or not str(pv).strip() or str(pv).strip() == "None"


def main():
    dry = "--dry" in sys.argv

    repo = gh("repos/%s/security-advisories?per_page=100" % REPO)

    # ---- ASSERT1
    if len(repo) != EXPECT_TOTAL:
        sys.exit("[ASSERT1 FAIL] 仓库级 advisory %d 条,基线 %d —— 上游动了,先更新结论再生成"
                 % (len(repo), EXPECT_TOTAL))
    for day, expect in EXPECT_BATCHES.items():
        n = len([a for a in repo if (a.get("published_at") or "").startswith(day)])
        if n != expect:
            sys.exit("[ASSERT1 FAIL] %s 那批 %d 条,基线 %d" % (day, n, expect))
    for a in repo:
        if a.get("state") != "published":
            sys.exit("[ASSERT1 FAIL] %s state=%s" % (a["ghsa_id"], a.get("state")))
        if a.get("withdrawn_at"):
            sys.exit("[ASSERT1 FAIL] %s 已撤回(withdrawn_at=%s)" % (a["ghsa_id"], a["withdrawn_at"]))
        if a["ghsa_id"] not in TITLES:
            sys.exit("[ASSERT1 FAIL] %s 没有中文标题 —— 新出现的条目,先读原文再补" % a["ghsa_id"])
    print("✅ ASSERT1:仓库级 %d 条(%s),全部 published、未撤回"
          % (len(repo), " / ".join("%s 那批 %d 条" % kv for kv in sorted(EXPECT_BATCHES.items()))))

    rows = []
    missing = set()
    diverge = {}
    sev_diverge = {}
    for a in repo:
        ghsa = a["ghsa_id"]
        repo_by_line = {}
        for v in a.get("vulnerabilities") or []:
            if v.get("package", {}).get("name") != PKG:
                continue
            rng, pv = v.get("vulnerable_version_range"), v.get("patched_versions")
            ln = range_line(rng)
            if no_fix(pv):
                # 🔴 修复版为空 ≠ 不受影响。只有原文写明该线停止维护才认,否则当脏数据停下。
                if ln != EOL_LINE or EOL_QUOTE not in (a.get("description") or ""):
                    sys.exit("[ASSERT1 FAIL] %s 在 %s 线 patched_versions=%r 为空,而原文没有 EOL 那句 —— "
                             "不许当「无修复版」也不许当「不受影响」,先读原文" % (ghsa, ln, pv))
                pv = None
            elif "," in pv:
                sys.exit("[ASSERT1 FAIL] %s patched_versions=%r,不是单值" % (ghsa, pv))
            elif line_of(pv) != ln:
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
                sev_diverge[ghsa] = (a.get("severity"), g.get("severity"))
            for v in g.get("vulnerabilities") or []:
                if v.get("package", {}).get("name") != PKG:
                    continue
                rng, fp = v.get("vulnerable_version_range"), v.get("first_patched_version")
                gln = range_line(rng)
                if not fp:
                    # 全局库的 null 只在仓库级同一条线也无修复版时才认
                    if not any(x[1] is None for x in repo_by_line.get(gln, [])):
                        sys.exit("[ASSERT7 FAIL] %s 全局库 %s 线没有 first_patched_version,而仓库级有修复版"
                                 % (ghsa, gln))
                    fp = None
                glob_by_line.setdefault(gln, []).append((rng, fp))

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
    def fixes(ln, only_global=False):
        return [r["fix"] for r in rows if r["line"] == ln and r["fix"] and (r["in_global"] or not only_global)]

    got3 = max(fixes("3.x"), key=vkey)
    if got3 != EXPECT_FIX_3X:
        sys.exit("[ASSERT3 FAIL] 3.x 线交集 %s,预期 %s —— 上游动了,先更新结论再生成" % (got3, EXPECT_FIX_3X))
    if any(r["fix"] is None for r in rows if r["line"] == "3.x"):
        sys.exit("[ASSERT3 FAIL] 3.x 线出现了无修复版的条目 —— 口径变了")
    last2 = max(fixes("2.x"), key=vkey)
    if last2 != EXPECT_LAST_FIX_2X:
        sys.exit("[ASSERT3 FAIL] 2.x 线有修复的最高版本 %s,预期 %s" % (last2, EXPECT_LAST_FIX_2X))
    unfixed2 = {r["ghsa"] for r in rows if r["line"] == "2.x" and r["fix"] is None}
    if unfixed2 != EXPECT_UNFIXED_2X:
        sys.exit("[ASSERT3 FAIL] 2.x 线无修复版的集合变了\n  多出:%s\n  少了:%s"
                 % (sorted(unfixed2 - EXPECT_UNFIXED_2X) or "无", sorted(EXPECT_UNFIXED_2X - unfixed2) or "无"))
    dep3 = max(fixes("3.x", only_global=True), key=vkey)
    if dep3 != EXPECT_DEPENDABOT_FIX_3X:
        sys.exit("[ASSERT3 FAIL] 只按全局库算,3.x 交集是 %s,预期 %s" % (dep3, EXPECT_DEPENDABOT_FIX_3X))
    print("✅ ASSERT3:3.x 交集 = %s;2.x 有修复的最高到 %s、另有 %d 条无修复版;只按全局库算 3.x = %s"
          % (got3, last2, len(unfixed2), dep3))

    # ---- ASSERT4
    for v in CENTRAL_POSITIVE:
        st = central(v)
        if st != 200:
            sys.exit("[ASSERT4 FAIL] %s 在 Central 上是 %s,不是 200" % (v, st))
    st = central(SENTINEL)
    if st != 404:
        sys.exit("[ASSERT4 FAIL] 哨兵 %s 是 %s 不是 404 —— 探测方式本身坏了,读数作废" % (SENTINEL, st))
    all_versions = central_versions()
    if EXPECT_LAST_FIX_2X not in all_versions:
        sys.exit("[ASSERT4 FAIL] 版本表里没有 %s —— 版本表读数不可信" % EXPECT_LAST_FIX_2X)
    newer2 = [v for v in all_versions if v.startswith("2.") and vkey(v) > vkey(EXPECT_LAST_FIX_2X)]
    if newer2:
        sys.exit("[ASSERT4 FAIL] 2.x 线出了比 %s 更新的版本 %s —— 「2.x 不再修」要重新核"
                 % (EXPECT_LAST_FIX_2X, newer2))
    print("✅ ASSERT4:Central %s 均 200;哨兵 %s 为 404;2.x 线最新仍是 %s(版本表共 %d 个版本)"
          % (" / ".join(CENTRAL_POSITIVE), SENTINEL, EXPECT_LAST_FIX_2X, len(all_versions)))

    # ---- ⭐ ASSERT5
    def hits_of(ver):
        out = {}
        for r in rows:
            if r["line"] == line_of(ver) and in_range(r["range"], ver):
                out.setdefault(r["ghsa"], r)
        return out

    h2 = hits_of(LAST_2X)
    if set(h2) != EXPECT_UNFIXED_2X or any(r["fix"] is not None for r in h2.values()):
        sys.exit("[ASSERT5 FAIL] 2.x 终版 %s 命中 %s,预期恰好是那 %d 条无修复版的 —— 承重墙变了,停下来重新定位"
                 % (LAST_2X, sorted(h2), len(EXPECT_UNFIXED_2X)))
    highs2 = sorted(g for g, r in h2.items() if r["severity"] in ("high", "critical"))
    if len(highs2) != 2:
        sys.exit("[ASSERT5 FAIL] %s 命中的 high 是 %s,预期 2 条" % (LAST_2X, highs2))
    h13 = hits_of(PREV_3X)
    if len(h13) != 5 or {r["fix"] for r in h13.values()} != {CLEAN_3X}:
        sys.exit("[ASSERT5 FAIL] %s 命中 %s,预期 5 条且全部 %s 修" % (PREV_3X, sorted(h13), CLEAN_3X))
    if hits_of(CLEAN_3X):
        sys.exit("[ASSERT5 FAIL] %s 应一条不中,实际 %s" % (CLEAN_3X, sorted(hits_of(CLEAN_3X))))
    print("✅ ASSERT5:%s 命中 %d 条全部无修复版(high %d 条:%s);%s 命中 5 条全部 %s 修;%s 一条不中"
          % (LAST_2X, len(h2), len(highs2), ", ".join(highs2), PREV_3X, CLEAN_3X, CLEAN_3X))

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
    if sev_diverge != EXPECT_SEV_DIVERGE:
        sys.exit("[ASSERT7 FAIL] 仓库级与全局库的严重度分歧变了\n  现在:%s\n  基线:%s"
                 % (sev_diverge, EXPECT_SEV_DIVERGE))
    print("✅ ASSERT7:区间分歧 %d 处、严重度分歧 %d 处,与基线一致(区间已取并集;严重度用仓库级)"
          % (len(diverge), len(sev_diverge)))

    print("✅ 七条断言全过。规则 %d 条(advisory %d 条)。" % (len(rows), len(repo)))

    java = render(rows, len(repo), len(missing), got3)
    if dry:
        print("\n--dry:不写文件。")
        return
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "..", "src", "main", "java", "dev", "mikko", "ahccheck", "RuleTable.java")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(java)
    print("→ 已写 %s" % os.path.normpath(out))


def render(rows, total, n_missing, migrate_to):
    def j(s):
        return "null" if s is None else '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = sorted(rows, key=lambda r: (r["line"], order.get(r["severity"], 9), r["ghsa"], r["range"]))
    consts = (
        "    /** 规则表生成日:全局库收录状态({@code inGlobal})是这一天的快照,之后可能已经补收。 */\n"
        "    static final String AS_OF = %s;\n\n"
        "    /** 仓库级 advisory 条数。 */\n"
        "    static final int ADVISORIES = %d;\n\n"
        "    /** 生成日全局库未收录的条数。 */\n"
        "    static final int MISSING_GLOBAL = %d;\n\n"
        "    /** 官方已宣布停止维护的版本线 —— 这条线上修复版为 null 的规则 = 「本线无修复版」。 */\n"
        "    static final String EOL_LINE = %s;\n\n"
        "    /** 停止维护的线要修完只能迁去的版本(3.x 线当前交集修复版)。 */\n"
        "    static final String EOL_MIGRATE_TO = %s;\n\n"
        "    /** 官方原文(09-24 那批 advisory 的 Patches 段逐条都有这一句)。 */\n"
        "    static final String EOL_QUOTE = %s;\n"
        % (j(AS_OF), total, n_missing, j(EOL_LINE), j(migrate_to),
           j(EOL_QUOTE + ". Upgrade to " + migrate_to + ".")))
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
 * <p>来源是 AsyncHttpClient 的<b>仓库级</b> security advisory(@TOTAL@ 条),不是 GitHub 全局 advisory 库 ——
 * 全局库(Dependabot / OSV 读的那个)到 @ASOF@ 仍缺其中 @MISS@ 条。
 * {@code inGlobal} 字段记的就是「生成那天 Dependabot 看不看得见这一条」。
 *
 * <p>🔴 {@code fix} 为 null = <b>这条线上没有修复版</b>(官方已宣布 2.x 停止维护),不是「不受影响」。
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

@CONSTS@
    /**
     * 一条 advisory 在一条版本线上的一个区间。
     *
     * @param fix      修复版;null = 本线无修复版(见 {@link RuleTable#EOL_LINE})
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
    header = (header.replace("@TOTAL@", str(total)).replace("@ASOF@", AS_OF)
              .replace("@MISS@", str(n_missing)).replace("@CONSTS@", consts))
    return header + "\n".join(body) + footer


if __name__ == "__main__":
    main()
