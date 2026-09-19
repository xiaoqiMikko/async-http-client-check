package dev.mikko.ahccheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 拿一个 async-http-client 版本,判出它中了 21 条里的哪几条、以及一次修完要升到哪。 */
final class Judge {

    /** 判定结果。 */
    record Verdict(String version, String line, List<RuleTable.Rule> hits,
                   String fixAll, String dependabotFix, List<String> warnings, String unknownReason) {

        boolean judged() { return unknownReason == null; }
        boolean clean()  { return judged() && hits.isEmpty(); }

        /** 命中里有几条是全局库(Dependabot / OSV)看不见的。 */
        long invisible() { return hits.stream().filter(r -> !r.inGlobal()).count(); }
    }

    static Verdict judge(String version) {
        String line = Versions.line(version);
        if (line == null) {
            // 🔴 判不了就说判不了。返回「没中」会让用户以为自己安全。
            return new Verdict(version, null, List.of(), null, null, List.of(),
                    "版本号解析不了(认得的后缀只有 alpha/Beta/M/RC/CR/Final)");
        }
        if (!line.equals("2.x") && !line.equals("3.x")) {
            return new Verdict(version, line, List.of(), null, null, List.of(),
                    "这 21 条 advisory 只覆盖 2.x 与 3.x 线," + line + " 线不在覆盖范围内 —— 不等于安全"
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

        String fixAll = max(hits.stream().map(RuleTable.Rule::fix).toList());
        String dependabotFix = max(hits.stream().filter(RuleTable.Rule::inGlobal).map(RuleTable.Rule::fix).toList());
        return new Verdict(version, line, hits, fixAll, dependabotFix, warnings, null);
    }

    private static String max(List<String> vs) {
        return vs.stream().reduce((a, b) -> Versions.compare(a, b) >= 0 ? a : b).orElse(null);
    }

    private Judge() { }
}
