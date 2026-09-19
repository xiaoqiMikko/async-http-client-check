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
    // ⭐ 承重墙:Dependabot 叫 3.x 用户升的 3.0.12,自己还中 5 条,且这 5 条全局库全都没收
    // ------------------------------------------------------------------

    @Test
    void 三点零点十二中五条且全部全局库未收录() {
        Judge.Verdict v = Judge.judge("3.0.12");
        assertEquals(List.of("GHSA-f9m8-cv68-674w", "GHSA-jmqq-x5g9-9p2w", "GHSA-qhv6-3pmh-95q4",
                        "GHSA-rqf5-2wxv-rjf4", "GHSA-vvp4-63h8-v5pm"), ghsas(v));
        assertTrue(v.hits().stream().noneMatch(RuleTable.Rule::inGlobal),
                "3.0.12 命中的 5 条都应标「全局库未收录」");
        assertEquals(5, v.invisible());
        assertEquals(2, v.hits().stream().filter(r -> r.severity().equals("high")).count(),
                "其中 high 应是 2 条(jmqq / rqf5)");
        assertEquals("3.0.13", v.fixAll());
        assertNull(v.dependabotFix(), "全局库一条都没收,Dependabot 给不出任何目标");
    }

    @Test
    void 三点零点十三干净() {
        Judge.Verdict v = Judge.judge("3.0.13");
        assertTrue(v.clean(), "3.0.13 应一条不中,实际:" + ghsas(v));
    }

    @Test
    void 三点零点十一_Dependabot只会叫你升到三点零点十二() {
        Judge.Verdict v = Judge.judge("3.0.11");
        assertEquals("3.0.13", v.fixAll());
        assertEquals("3.0.12", v.dependabotFix(),
                "只按全局库算,3.0.11 的目标是 3.0.12 —— 那正是 Dependabot 会给的数字");
        assertTrue(v.invisible() > 0);
        // 3.0.11 对「严格小于 3.0.11」那条(CVE-2026-55688)安全,对「小于等于 3.0.11」那几条中招
        assertFalse(hit(v, "GHSA-m452-q8c9-rg2f"));
        assertTrue(hit(v, "GHSA-v9f2-7rw2-gr2x"));
        assertTrue(hit(v, "GHSA-7grg-jcf7-rpmx"), "CVE-2026-85721 解压炸弹,区间含 3.0.11");
        // 只影响 3.0.12 的那条不许命中 3.0.11
        assertFalse(hit(v, "GHSA-qhv6-3pmh-95q4"));
    }

    @Test
    void 二点十二点三中一大片且目标二点十六点一() {
        Judge.Verdict v = Judge.judge("2.12.3");
        assertEquals("2.16.1", v.fixAll());
        assertTrue(hit(v, "GHSA-mfj5-cf8g-g2fv"),
                "CVE-2024-53990 的 2.x 区间只在全局库里(>= 2.1.0, < 2.12.4)—— 只信仓库级会漏掉它");
        assertTrue(v.hits().stream().allMatch(r -> r.line().equals("2.x")));
        assertTrue(v.hits().size() >= 15, "实际 " + v.hits().size());
    }

    @Test
    void 二点十六点零只剩八月那批() {
        Judge.Verdict v = Judge.judge("2.16.0");
        assertEquals("2.16.1", v.fixAll());
        // 严格小于 2.16.0 的 CVE-2026-55688 对 2.16.0 安全
        assertFalse(hit(v, "GHSA-m452-q8c9-rg2f"));
        assertTrue(hit(v, "GHSA-rqf5-2wxv-rjf4"));
        assertEquals("2.16.1", v.dependabotFix(), "2.x 线全局库收的几条也要 2.16.1");
    }

    @Test
    void 二点十六点一干净() {
        assertTrue(Judge.judge("2.16.1").clean());
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
    void 规则表覆盖二十一条且标了十三条未收录() {
        assertEquals(21, RuleTable.RULES.stream().map(RuleTable.Rule::ghsa).distinct().count());
        assertEquals(13, RuleTable.RULES.stream().filter(r -> !r.inGlobal())
                .map(RuleTable.Rule::ghsa).distinct().count());
    }
}
