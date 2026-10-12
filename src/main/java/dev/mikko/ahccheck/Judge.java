package dev.mikko.ahccheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 拿一个 async-http-client 版本,判出它中了规则表里的哪几条、以及一次修完要升到哪。 */
final class Judge {

    /**
     * 判定结果。
     *
     * @param fixAll        命中的条目里<b>有修复版的那些</b>一次修完要升到的版本;命中的全都没有修复版时为 null
     * @param dependabotFix 只按全局库收录的条目算出来的目标版本
     * @param migrateTo     命中了「本线无修复版」的条目时,要修完只能迁去的版本;否则为 null
     */
    record Verdict(String version, String line, List<RuleTable.Rule> hits,
                   String fixAll, String dependabotFix, String migrateTo,
                   List<String> warnings, String unknownReason) {

        boolean judged() { return unknownReason == null; }
        boolean clean()  { return judged() && hits.isEmpty(); }

        /** 命中里有几条是全局库(Dependabot / OSV)看不见的。 */
        long invisible() { return hits.stream().filter(r -> !r.inGlobal()).count(); }

        /** 命中里有几条在本线上没有修复版(该线已停止维护)。 */
        long unfixed() { return hits.stream().filter(r -> r.fix() == null).count(); }

        /**
         * 升到 {@link #fixAll} 之后还会中几条。
         * 🔴 必须拿升完的版本重新判:有的 advisory 下界比你现在的版本高,升上去反而新中一条。
         */
        long remainingAfterFixAll() {
            return fixAll == null ? hits.size() : judge(fixAll).hits().size();
        }
    }

    static Verdict judge(String version) {
        String line = Versions.line(version);
        if (line == null) {
            // 🔴 判不了就说判不了。返回「没中」会让用户以为自己安全。
            return new Verdict(version, null, List.of(), null, null, null, List.of(),
                    "版本号解析不了(认得的后缀只有 alpha/Beta/M/RC/CR/Final)");
        }
        if (!line.equals("2.x") && !line.equals("3.x")) {
            return new Verdict(version, line, List.of(), null, null, null, List.of(),
                    "这 " + RuleTable.ADVISORIES + " 条 advisory 只覆盖 2.x 与 3.x 线," + line
                            + " 线不在覆盖范围内 —— 不等于安全"
                            + "(1.x 是旧坐标 com.ning:async-http-client,本工具不判)");
        }

        // 同一条 advisory 在同一条线上可能有两个区间(仓库级 + 全局库并集),命中只算一次。
        Map<String, RuleTable.Rule> byGhsa = new LinkedHashMap<>();
        for (RuleTable.Rule r : RuleTable.RULES) {
            if (!r.line().equals(line)) continue;
            // 🔴 区间里的算子由 Ranges 逐条按原文判,不许在这里统一。
            if (Ranges.contains(r.range(), version)) byGhsa.putIfAbsent(r.ghsa(), r);
        }
        List<RuleTable.Rule> hits = new ArrayList<>(byGhsa.values());

        List<String> warnings = new ArrayList<>();
        if (Versions.isPreRelease(version)) {
            // 大部分区间的下界从正式版起算(>= 3.0.0 / >= 2.0.0),预发布版会掉在区间外。
            // 🔴 那是「advisory 没写到」,不是「不受影响」—— 必须说出来,不许落进默认分支「安全」。
            warnings.add("你的 " + version + " 是预发布版。多数 advisory 的下界从正式版起算,"
                    + "预发布版掉在区间外不等于不受影响 —— 建议直接升到本线的修复版。");
        }

        // 🔴 修复版为 null = 本线无修复版,不参与「升到哪」的计算 —— 把它当成一个很小的版本号
        // 会得出「升到 2.16.1 就修完了」,而那正是这一版要纠正的结论。
        String fixAll = max(hits.stream().map(RuleTable.Rule::fix).filter(f -> f != null).toList());
        String dependabotFix = max(hits.stream().filter(RuleTable.Rule::inGlobal)
                .map(RuleTable.Rule::fix).filter(f -> f != null).toList());
        boolean anyUnfixed = hits.stream().anyMatch(r -> r.fix() == null);
        String migrateTo = anyUnfixed ? RuleTable.EOL_MIGRATE_TO : null;
        return new Verdict(version, line, hits, fixAll, dependabotFix, migrateTo, warnings, null);
    }

    private static String max(List<String> vs) {
        return vs.stream().reduce((a, b) -> Versions.compare(a, b) >= 0 ? a : b).orElse(null);
    }

    private Judge() { }
}
