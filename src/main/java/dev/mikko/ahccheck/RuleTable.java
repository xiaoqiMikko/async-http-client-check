package dev.mikko.ahccheck;

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
        add("GHSA-mfj5-cf8g-g2fv", "CVE-2024-53990", "CookieStore 覆盖显式设置的 Cookie", "critical", "2.x", ">= 2.1.0, < 2.12.4", "2.12.4", true, "全局库");
        add("GHSA-7grg-jcf7-rpmx", "CVE-2026-85721", "HTTP/1.1 响应解压无上限 -> 解压炸弹拒绝服务", "high", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", true, "仓库级");
        add("GHSA-fmxf-pm6p-7xgm", "CVE-2026-45300", "跨源重定向不剥离 Cookie 头", "high", "2.x", ">= 2.0.0, < 2.15.0", "2.15.0", true, "仓库级");
        add("GHSA-jmqq-x5g9-9p2w", null, "重放到另一主机时把原主机的请求与凭据发给新主机", "high", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-rqf5-2wxv-rjf4", null, "Digest 质询缺可用 nonce -> 降级 Basic,明文发送密码", "high", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-v9f2-7rw2-gr2x", null, "代理拒绝 CONNECT 时,源站凭据明文发给代理", "high", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-x5w6-vm3f-pp6f", "CVE-2026-85719", "SOCKS 代理凭据经明文 HTTP 发给源站", "high", "2.x", ">= 2.1.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-3wp9-xfwm-rjjf", null, "WebSocket 走 CONNECT 隧道时代理凭据发给源站", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-cf59-3jcr-vfhw", null, "断点续传索引文件全局可读且跟随预置符号链接", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-cmxv-58fp-fm3g", "CVE-2026-40490", "跨源重定向把 Authorization 凭据泄给不可信域", "medium", "2.x", ">= 2.0.0, < 2.14.5", "2.14.5", true, "仓库级");
        add("GHSA-f8m2-889x-vw4x", "CVE-2026-85717", "客户端级 realm 凭据在跨源重定向时被重发", "medium", "2.x", ">= 2.14.5, <= 2.16.0", "2.16.1", true, "仓库级");
        add("GHSA-f9m8-cv68-674w", null, "Cookie Domain 不查公共后缀表 -> 可对 co.uk 种 cookie", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-m452-q8c9-rg2f", "CVE-2026-55688", "ThreadSafeCookieStore 为无关域存 cookie(cookie tossing)", "medium", "2.x", ">= 2.0.0, < 2.16.0", "2.16.0", true, "仓库级");
        add("GHSA-qpfv-56x8-xgx4", null, "URL userinfo 凭据写进发给 HTTP 代理的请求行", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-vvp4-63h8-v5pm", null, "连接池 key 不含认证主体 -> NTLM/Negotiate 连接跨身份复用", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-xr57-gcx8-52hf", "CVE-2026-85720", "明文 CONNECT 请求把源站凭据发给代理", "medium", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", true, "仓库级");
        add("GHSA-mfj3-87qq-382v", null, "Digest cnonce 用非密码学随机源生成", "low", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-rwhr-j9rv-85f8", null, "WebSocket 握手 Sec-WebSocket-Accept 校验失败后仍继续", "low", "2.x", ">= 2.0.0, <= 2.16.0", "2.16.1", false, "仓库级");
        add("GHSA-mfj5-cf8g-g2fv", "CVE-2024-53990", "CookieStore 覆盖显式设置的 Cookie", "critical", "3.x", "3.0.0", "3.0.1", true, "仓库级");
        add("GHSA-mfj5-cf8g-g2fv", "CVE-2024-53990", "CookieStore 覆盖显式设置的 Cookie", "critical", "3.x", ">= 3.0.0.Beta1, < 3.0.1", "3.0.1", true, "全局库");
        add("GHSA-7grg-jcf7-rpmx", "CVE-2026-85721", "HTTP/1.1 响应解压无上限 -> 解压炸弹拒绝服务", "high", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", true, "仓库级");
        add("GHSA-fmxf-pm6p-7xgm", "CVE-2026-45300", "跨源重定向不剥离 Cookie 头", "high", "3.x", ">= 3.0.0.Beta1, < 3.0.10", "3.0.10", true, "仓库级");
        add("GHSA-jmqq-x5g9-9p2w", null, "重放到另一主机时把原主机的请求与凭据发给新主机", "high", "3.x", ">= 3.0.0, <= 3.0.12", "3.0.13", false, "仓库级");
        add("GHSA-rqf5-2wxv-rjf4", null, "Digest 质询缺可用 nonce -> 降级 Basic,明文发送密码", "high", "3.x", ">= 3.0.0.Beta1, <= 3.0.12", "3.0.13", false, "仓库级");
        add("GHSA-v9f2-7rw2-gr2x", null, "代理拒绝 CONNECT 时,源站凭据明文发给代理", "high", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-x5w6-vm3f-pp6f", "CVE-2026-85719", "SOCKS 代理凭据经明文 HTTP 发给源站", "high", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-3wp9-xfwm-rjjf", null, "WebSocket 走 CONNECT 隧道时代理凭据发给源站", "medium", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-cf59-3jcr-vfhw", null, "断点续传索引文件全局可读且跟随预置符号链接", "medium", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-cmxv-58fp-fm3g", "CVE-2026-40490", "跨源重定向把 Authorization 凭据泄给不可信域", "medium", "3.x", ">= 3.0.0.Beta1, < 3.0.9", "3.0.9", true, "仓库级");
        add("GHSA-f8m2-889x-vw4x", "CVE-2026-85717", "客户端级 realm 凭据在跨源重定向时被重发", "medium", "3.x", ">= 3.0.9, <= 3.0.11", "3.0.12", true, "仓库级");
        add("GHSA-f9m8-cv68-674w", null, "Cookie Domain 不查公共后缀表 -> 可对 co.uk 种 cookie", "medium", "3.x", ">= 3.0.0, <= 3.0.12", "3.0.13", false, "仓库级");
        add("GHSA-gcmv-gr82-6m8v", "CVE-2026-85718", "TLS 握手失败泄漏连接许可 -> 按主机拒绝服务", "medium", "3.x", ">= 3.0.8, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-m452-q8c9-rg2f", "CVE-2026-55688", "ThreadSafeCookieStore 为无关域存 cookie(cookie tossing)", "medium", "3.x", ">= 3.0.0.Beta1, < 3.0.11", "3.0.11", true, "仓库级");
        add("GHSA-qpfv-56x8-xgx4", null, "URL userinfo 凭据写进发给 HTTP 代理的请求行", "medium", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-vvp4-63h8-v5pm", null, "连接池 key 不含认证主体 -> NTLM/Negotiate 连接跨身份复用", "medium", "3.x", ">= 3.0.0, <= 3.0.12", "3.0.13", false, "仓库级");
        add("GHSA-xr57-gcx8-52hf", "CVE-2026-85720", "明文 CONNECT 请求把源站凭据发给代理", "medium", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", true, "仓库级");
        add("GHSA-fj9w-c36g-h5x8", "CVE-2026-85716", "SCRAM/Digest 双向认证响应未校验", "low", "3.x", ">= 3.0.8, <= 3.0.11", "3.0.12", true, "仓库级");
        add("GHSA-mfj3-87qq-382v", null, "Digest cnonce 用非密码学随机源生成", "low", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
        add("GHSA-qhv6-3pmh-95q4", null, "对端给 qop=auth-int 即关掉 Digest 双向认证", "low", "3.x", "= 3.0.12", "3.0.13", false, "仓库级");
        add("GHSA-rwhr-j9rv-85f8", null, "WebSocket 握手 Sec-WebSocket-Accept 校验失败后仍继续", "low", "3.x", ">= 3.0.0, <= 3.0.11", "3.0.12", false, "仓库级");
    }

    private RuleTable() { }
}
