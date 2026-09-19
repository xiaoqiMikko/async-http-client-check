# -*- coding: utf-8 -*-
"""async-http-client-check 真实 jar 端到端回测。

🔴 单测用的是自己造的 zip;这里用 Central 上的**真 jar**,验的是「真实世界的 jar 结构认不认得出」。
   前几注的经验:造的 zip 全过、真 jar 认不出,是常见死法(第 22 注 Thymeleaf 没有 maven/ 目录那次)。

用法:  先 mvn package,再  python -u tools/e2e_real_jars.py
       每个场景的完整输出另存到 tools/e2e/out-<场景>.txt(已 gitignore)。
"""
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
JAR = os.path.join(HERE, "..", "target", "async-http-client-check-0.1.0.jar")
WORK = os.path.join(HERE, "e2e")
CENTRAL = ("https://repo1.maven.org/maven2/org/asynchttpclient/async-http-client/%s/"
           "async-http-client-%s.jar")

fails = []


def fetch(version):
    os.makedirs(WORK, exist_ok=True)
    p = os.path.join(WORK, "async-http-client-%s.jar" % version)
    if not os.path.exists(p):
        with urllib.request.urlopen(CENTRAL % (version, version), timeout=120) as r, open(p, "wb") as f:
            f.write(r.read())
    return p


def run(name, *args):
    """🔴 按系统编码(GBK)先解 —— Windows 上 java 按系统编码写 stdout,用 utf-8 读会全是乱码,
    而乱码会让每一条中文断言都失败,看起来像工具坏了。"""
    r = subprocess.run(["java", "-jar", JAR] + list(args), capture_output=True)

    def dec(b):
        for enc in ("gbk", "utf-8"):
            try:
                return b.decode(enc)
            except UnicodeDecodeError:
                continue
        return b.decode("gbk", "replace")
    out = dec(r.stdout or b"") + dec(r.stderr or b"")
    with open(os.path.join(WORK, "out-%s.txt" % name), "w", encoding="utf-8") as f:
        f.write("exit=%d\n%s" % (r.returncode, out))
    return r.returncode, out


def ids(out):
    return sorted(set(re.findall(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]{14})\b", out)))


def check(name, cond, detail=""):
    print(("  ✅ " if cond else "  ❌ ") + name + ("" if cond else "  ← " + detail))
    if not cond:
        fails.append(name)


def fresh(name):
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    return d


def hit_block(out):
    """只取「中了 N 条」那一段,避免把用法说明里的编号算进来。"""
    m = re.search(r"中了 (\d+) 条", out)
    return int(m.group(1)) if m else 0


print("=" * 78)
print("场景 1:真 jar 3.0.12 —— Dependabot 叫你升到的版本,本工具应判中 5 条且全部未收录")
d = fresh("s1")
shutil.copy(fetch("3.0.12"), d)
code, out = run("s1", d)
check("退出码 1(中了)", code == 1, "实际 %d" % code)
check("从 pom.properties 认出", "pom.properties" in out, out[:300])
check("中了 5 条", hit_block(out) == 5, "实际 %d" % hit_block(out))
got = [x for x in ids(out) if x.startswith("GHSA-")]
want = ["GHSA-f9m8-cv68-674w", "GHSA-jmqq-x5g9-9p2w", "GHSA-qhv6-3pmh-95q4",
        "GHSA-rqf5-2wxv-rjf4", "GHSA-vvp4-63h8-v5pm"]
check("编号就是那 5 条 GHSA", got == want, "实际 %s" % got)
check("5 条都标了「未收录」", out.count("Dependabot/全局库:未收录") == 5,
      "实际 %d" % out.count("Dependabot/全局库:未收录"))
check("没有一条标「已收录」", "Dependabot/全局库:已收录" not in out)
check("给出 3.0.13", "一次修完这几条要升到:3.0.13" in out)

print()
print("=" * 78)
print("场景 2:真 jar 3.0.13 —— 应干净")
d = fresh("s2")
shutil.copy(fetch("3.0.13"), d)
code, out = run("s2", d)
check("退出码 0", code == 0, "实际 %d;%s" % (code, out[-300:]))
check("说了一条都没中", "一条都没中" in out)

print()
print("=" * 78)
print("场景 3:真 jar 2.12.3 —— 2.x 老版本,应中一大片、目标 2.16.1,且含 CVE-2024-53990(只在全局库的 2.x 区间)")
d = fresh("s3")
shutil.copy(fetch("2.12.3"), d)
code, out = run("s3", d)
check("退出码 1", code == 1, "实际 %d" % code)
check("中了 >= 15 条", hit_block(out) >= 15, "实际 %d" % hit_block(out))
check("含 CVE-2024-53990", "CVE-2024-53990" in out)
check("给出 2.16.1", "一次修完这几条要升到:2.16.1" in out)

print()
print("=" * 78)
print("场景 4:⭐ fat-jar + war 形态(真 jar 改名塞进 BOOT-INF/lib 与 WEB-INF/lib)")
d = fresh("s4")
with zipfile.ZipFile(os.path.join(d, "app.jar"), "w") as z:
    z.write(fetch("3.0.11"), "BOOT-INF/lib/lib-a.jar")     # 🔴 故意改名:证明不靠文件名认
    z.writestr("BOOT-INF/classes/App.class", b"\xca\xfe\xba\xbe")
with zipfile.ZipFile(os.path.join(d, "app.war"), "w") as z:
    z.write(fetch("2.16.1"), "WEB-INF/lib/x.jar")
code, out = run("s4", d)
check("退出码 1(3.0.11 中了)", code == 1, "实际 %d" % code)
check("嵌套路径写出来了(fat-jar)", "!/BOOT-INF/lib/lib-a.jar" in out, out[:600])
check("嵌套路径写出来了(war)", "!/WEB-INF/lib/x.jar" in out)
check("3.0.11 判出 Dependabot 只会叫你升 3.0.12", "会叫你升到 3.0.12" in out)
check("2.16.1 那一段干净", "一条都没中" in out)
check("结论给出 3.0.13", "需要升到 3.0.13" in out)

print()
print("=" * 78)
print("场景 5:阴性对照 —— 只有无关 jar,必须说『没找到』且退出码 2")
d = fresh("s5")
with zipfile.ZipFile(os.path.join(d, "guava.jar"), "w") as z:
    z.writestr("META-INF/maven/com.google.guava/guava/pom.properties",
               "artifactId=guava\ngroupId=com.google.guava\nversion=32.0.0\n")
code, out = run("s5", d)
check("退出码 2", code == 2, "实际 %d" % code)
check("说的是『没找到』", "没找到" in out)

print()
print("=" * 78)
print("场景 6:☠️ 坏 jar + 干净真 jar —— 退出码必须是 4,不许是 0")
d = fresh("s6")
shutil.copy(fetch("3.0.13"), d)
with open(os.path.join(d, "broken.jar"), "wb") as f:
    f.write(b"this is definitely not a zip file")
code, out = run("s6", d)
check("报了读取失败", "读取失败" in out)
check("退出码 4", code == 4, "实际 %d" % code)

print()
print("=" * 78)
print("场景 7:--version-of")
code, out = run("s7a", "--version-of", "3.0.12")
check("3.0.12 退出码 1", code == 1)
code, out = run("s7b", "--version-of", "不是版本号")
check("认不出的版本号 → 退出码 2", code == 2, "实际 %d" % code)

print()
print("=" * 78)
if fails:
    print("❌ 端到端回测失败 %d 项:%s" % (len(fails), fails))
    sys.exit(1)
print("✅ 端到端回测全过(7 个场景,用的是 Central 上的真 jar)")
