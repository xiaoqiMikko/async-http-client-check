package dev.mikko.ahccheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JudgeTest {

    private static List<String> ghsas(Judge.Verdict v) {
        return v.hits().stream().map(RuleTable.Rule::ghsa).sorted().toList();
    }

    private static boolean hit(Judge.Verdict v, String ghsa) {
        return v.hits().stream().anyMatch(r -> r.ghsa().equals(ghsa));
    }

    // ------------------------------------------------------------------
    // ⭐ 承重墙(v0.2.0):2.x 线已停止维护 —— 终版 2.16.1 仍中 5 条,且这 5 条在 2.x 上没有修复版
    // ------------------------------------------------------------------

    private static final List<String> BATCH_0924 = List.of(
            "GHSA-2jwh-9rmr-j4xf", "GHSA-p2jm-6hj6-9rjg", "GHSA-qjr7-w8pj-pmv9",
            "GHSA-v2j5-22fr-j62r", "GHSA-x8v2-478q-2hvg");

    @Test
    void 二点十六点一仍中五条_全部无修复版_只能迁到三点零点十四() {
        Judge.Verdict v = Judge.judge("2.16.1");
        assertEquals(BATCH_0924, ghsas(v));
        assertEquals(5, v.unfixed());
        assertTrue(v.hits().stream().allMatch(r -> r.fix() == null), "这 5 条在 2.x 上都不该有修复版");
        assertEquals(2, v.hits().stream().filter(r -> r.severity().equals("high")).count(),
                "其中 high 应是 2 条(v2j5 / x8v2)");
        assertNull(v.fixAll(), "2.x 线内没有任何版本能修掉它们 —— 不许给出一个 2.x 的版本号当答案");
        assertEquals("3.0.14", v.migrateTo());
        assertFalse(v.clean(), "v0.1.0 把 2.16.1 判成干净,那个结论 2026-09-24 起已经不成立");
    }

    @Test
    void 二点十六点零_本线最多升到二点十六点一_升完仍不干净() {
        Judge.Verdict v = Judge.judge("2.16.0");
        assertEquals("2.16.1", v.fixAll(), "有修复版的那几条仍要 2.16.1");
        assertEquals(5, v.unfixed());
        assertEquals("3.0.14", v.migrateTo());
        // 严格小于 2.16.0 的 CVE-2026-55688 对 2.16.0 安全
        assertFalse(hit(v, "GHSA-m452-q8c9-rg2f"));
        assertTrue(hit(v, "GHSA-rqf5-2wxv-rjf4"));
    }

    @Test
    void 二点十二点三中一大片_无修复版的是四条不是五条() {
        Judge.Verdict v = Judge.judge("2.12.3");
        assertEquals("2.16.1", v.fixAll());
        assertEquals("3.0.14", v.migrateTo());
        assertTrue(hit(v, "GHSA-mfj5-cf8g-g2fv"),
                "CVE-2024-53990 的 2.x 区间只在全局库里(>= 2.1.0, < 2.12.4)—— 只信仓库级会漏掉它");
        assertTrue(v.hits().stream().allMatch(r -> r.line().equals("2.x")));
        assertTrue(v.hits().size() >= 15, "实际 " + v.hits().size());
        // CVE-2026-107229 的 2.x 区间从 2.16.0 起,2.12.3 不在里面
        assertFalse(hit(v, "GHSA-qjr7-w8pj-pmv9"));
        // …所以升到 2.16.1 之后剩下的是 5 条,不是现在的 4 条(升上去反而新中这一条)
        assertEquals(5, v.remainingAfterFixAll());
        assertEquals(4, v.unfixed());
    }

    @Test
    void 三点零点十三中五条_全部三点零点十四修() {
        Judge.Verdict v = Judge.judge("3.0.13");
        assertEquals(BATCH_0924, ghsas(v), "09-24 那批 5 条,3.x 上有修复版");
        assertTrue(v.hits().stream().allMatch(r -> "3.0.14".equals(r.fix())));
        assertEquals(0, v.unfixed());
        assertNull(v.migrateTo(), "3.x 线有修复版,不存在「迁移」这回事");
        assertEquals("3.0.14", v.fixAll());
        assertEquals("3.0.14", v.dependabotFix(), "全局库收了其中 4 条,Dependabot 现在给的数字是对的");
        assertEquals(1, v.invisible(), "只有 CVE-2026-107229 全局库没收");
    }

    @Test
    void 三点零点十四干净() {
        Judge.Verdict v = Judge.judge("3.0.14");
        assertTrue(v.clean(), "3.0.14 应一条不中,实际:" + ghsas(v));
    }

    @Test
    void 三点零点十二_答案是三点零点十四_仍有三条全局库看不见() {
        Judge.Verdict v = Judge.judge("3.0.12");
        assertEquals("3.0.14", v.fixAll());
        for (String g : List.of("GHSA-f9m8-cv68-674w", "GHSA-jmqq-x5g9-9p2w", "GHSA-qhv6-3pmh-95q4",
                "GHSA-rqf5-2wxv-rjf4", "GHSA-vvp4-63h8-v5pm")) {
            assertTrue(hit(v, g), "v0.1.0 那 5 条仍应命中:" + g);
        }
        assertEquals(List.of("GHSA-qhv6-3pmh-95q4", "GHSA-qjr7-w8pj-pmv9", "GHSA-vvp4-63h8-v5pm"),
                v.hits().stream().filter(r -> !r.inGlobal()).map(RuleTable.Rule::ghsa).sorted().toList());
    }

    @Test
    void 三点零点十一_边界算子没被统一() {
        Judge.Verdict v = Judge.judge("3.0.11");
        assertEquals("3.0.14", v.fixAll());
        assertTrue(v.invisible() > 0);
        // 3.0.11 对「严格小于 3.0.11」那条(CVE-2026-55688)安全,对「小于等于 3.0.11」那几条中招
        assertFalse(hit(v, "GHSA-m452-q8c9-rg2f"));
        assertTrue(hit(v, "GHSA-v9f2-7rw2-gr2x"));
        assertTrue(hit(v, "GHSA-7grg-jcf7-rpmx"), "CVE-2026-85721 解压炸弹,区间含 3.0.11");
        // 只影响 3.0.12 的那条不许命中 3.0.11
        assertFalse(hit(v, "GHSA-qhv6-3pmh-95q4"));
    }

    @Test
    void 无修复版的条目只出现在已停止维护的那条线上() {
        assertTrue(RuleTable.RULES.stream().filter(r -> r.fix() == null)
                .allMatch(r -> r.line().equals(RuleTable.EOL_LINE)));
        assertEquals(5, RuleTable.RULES.stream().filter(r -> r.fix() == null)
                .map(RuleTable.Rule::ghsa).distinct().count());
    }

    // ------------------------------------------------------------------
    // 🔴 边界:算子逐条按原文判,不许统一
    // ------------------------------------------------------------------

    @Test
    void 显式等号只命中那一个版本() {
        assertTrue(hit(Judge.judge("3.0.12"), "GHSA-qhv6-3pmh-95q4"));
        assertFalse(hit(Judge.judge("3.0.11"), "GHSA-qhv6-3pmh-95q4"));
        assertFalse(hit(Judge.judge("3.0.13"), "GHSA-qhv6-3pmh-95q4"));
    }

    @Test
    void 裸版本号与全局库区间取并集_同一条只算一次() {
        Judge.Verdict v = Judge.judge("3.0.0");
        long n = v.hits().stream().filter(r -> r.ghsa().equals("GHSA-mfj5-cf8g-g2fv")).count();
        assertEquals(1, n, "3.0.0 同时落在裸版本 3.0.0 与全局库区间里,命中只能算一次");
        // Beta 只被全局库那段覆盖
        assertTrue(hit(Judge.judge("3.0.0.Beta2"), "GHSA-mfj5-cf8g-g2fv"));
        assertFalse(hit(Judge.judge("3.0.1"), "GHSA-mfj5-cf8g-g2fv"));
    }

    @Test
    void 两条线不串() {
        assertTrue(Judge.judge("3.0.5").hits().stream().allMatch(r -> r.line().equals("3.x")));
        assertTrue(Judge.judge("2.10.0").hits().stream().allMatch(r -> r.line().equals("2.x")));
    }

    // ------------------------------------------------------------------
    // 🔴 判不了 ≠ 没中
    // ------------------------------------------------------------------

    @Test
    void 认不出的版本号判不了而不是判安全() {
        Judge.Verdict v = Judge.judge("不是版本号");
        assertFalse(v.judged());
        assertFalse(v.clean());
    }

    @Test
    void 一点x线判不了() {
        Judge.Verdict v = Judge.judge("1.9.40");
        assertFalse(v.judged());
        assertTrue(v.unknownReason().contains("不等于安全"));
    }

    @Test
    void 预发布版带警告() {
        Judge.Verdict v = Judge.judge("2.0.0-RC1");
        assertTrue(v.judged());
        assertFalse(v.warnings().isEmpty(), "预发布版掉在区间外不等于不受影响,必须说出来");
    }

    @Test
    void 规则表覆盖二十六条且标了九条未收录_与生成的常量一致() {
        assertEquals(26, RuleTable.RULES.stream().map(RuleTable.Rule::ghsa).distinct().count());
        assertEquals(9, RuleTable.RULES.stream().filter(r -> !r.inGlobal())
                .map(RuleTable.Rule::ghsa).distinct().count());
        assertEquals(26, RuleTable.ADVISORIES);
        assertEquals(9, RuleTable.MISSING_GLOBAL);
    }
}
