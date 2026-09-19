package dev.mikko.ahccheck;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 解析 advisory 的 {@code vulnerable_version_range}。
 *
 * <p>21 条 advisory 里实际出现的写法(2026-09-19 逐条读过,不是猜的):
 * <pre>
 *   &gt;= 3.0.0, &lt;= 3.0.12        含等号上界
 *   &gt;= 3.0.0.Beta1, &lt; 3.0.11   严格小于上界
 *   = 3.0.12                  显式等号(GHSA-qhv6 只影响 3.0.12 一个版本)
 *   3.0.0                     裸版本号,等于精确匹配(CVE-2024-53990 的仓库级写法)
 * </pre>
 * 此外还认 {@code >} 与「只有下界」的写法 —— 本轮没出现,但它们是合法的 GHSA 写法。
 *
 * <p>🔴 <b>逐条按原文算子判,不许统一。</b> 同一个 3.0.11:对 {@code < 3.0.11} 安全,对 {@code <= 3.0.11} 中招。
 *
 * <p>🔴 <b>认不出的写法一律抛异常,不许静默当「不受影响」</b> ——
 * 默认分支是「安全」,所以解析失败会变成一句令人安心的错话。
 */
final class Ranges {

    /** 可选算子 + 版本号。算子缺省 = 精确等于(裸版本号)。 */
    private static final Pattern BOUND = Pattern.compile("^\\s*(>=|>|<=|<|=)?\\s*(\\d[^,\\s]*)\\s*$");

    /** @return v 是否落在 range 内 */
    static boolean contains(String range, String v) {
        if (range == null || range.isBlank()) {
            throw new IllegalArgumentException("空的版本区间 —— 判不了,不许当安全");
        }
        boolean in = true;
        for (String part : range.split(",", -1)) {
            Matcher m = BOUND.matcher(part);
            if (!m.matches() || Versions.parse(m.group(2)) == null) {
                throw new IllegalArgumentException("认不出的版本区间片段: '" + part + "' (整段: " + range + ")");
            }
            int c = Versions.compare(v, m.group(2));
            String op = m.group(1) == null ? "=" : m.group(1);
            in &= switch (op) {
                case ">=" -> c >= 0;
                case ">"  -> c > 0;
                case "<=" -> c <= 0;
                case "<"  -> c < 0;
                default   -> c == 0;   // "=" 与裸版本号
            };
        }
        return in;
    }

    private Ranges() { }
}
