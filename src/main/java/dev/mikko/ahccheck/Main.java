package dev.mikko.ahccheck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * async-http-client-check —— 离线判定 org.asynchttpclient:async-http-client 的仓库级 advisory
 * (条数见 {@link RuleTable#ADVISORIES},随规则表生成)。
 *
 * <p>退出码:0 = 没中(且每个文件都读进去了);1 = 中了;2 = 判不了(参数错、路径不存在、版本号认不出);
 * 4 = 有文件读不动。
 * 🔴 <b>「判不了」「读不动」必须和「没中」用不同的退出码</b> —— 混在一起,脚本里就再也分不出
 * 「扫过了很干净」和「根本没扫成」。
 */
public final class Main {

    /** 有文件读不动 —— 「我没能读它」不许在自动化里等于「通过」。 */
    static final int EXIT_UNREADABLE = 4;

    private static final String VERSION = "0.2.0";

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        } catch (Exception e) {
            System.err.println("[判不了] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
        }
    }

    static int run(String[] args) throws IOException {
        if (args.length == 0 || has(args, "-h") || has(args, "--help")) {
            usage();
            return args.length == 0 ? 2 : 0;
        }
        if (has(args, "--version")) {
            System.out.println("async-http-client-check " + VERSION);
            return 0;
        }

        // 形态一:直接给版本号
        int vi = indexOf(args, "--version-of");
        if (vi >= 0) {
            if (vi + 1 >= args.length) {
                System.err.println("[判不了] --version-of 后面要跟一个版本号,例如 3.0.12");
                return 2;
            }
            return report(Map.of(Scanner.TARGET, List.of(
                    new Scanner.Found(Scanner.TARGET, args[vi + 1], "(命令行给定)", "--version-of"))));
        }

        // 形态二:扫路径
        Path root = Path.of(args[0]);
        if (!Files.exists(root)) {
            System.err.println("[判不了] 路径不存在:" + root);
            return 2;
        }
        List<Scanner.Found> found = Scanner.scan(root);
        if (found.isEmpty()) {
            System.out.println("在 " + root + " 里没有找到任何 async-http-client 构件。");
            System.out.println();
            System.out.println("🔴 这读作「没找到」,不是「你没用 async-http-client」——");
            System.out.println("   本工具只认落地的 jar,不读 pom.xml。如果你的依赖还没打包下来,先 mvn package 再扫。");
            return 2;
        }

        Map<String, List<Scanner.Found>> byArtifact = new TreeMap<>();
        for (Scanner.Found f : found) {
            byArtifact.computeIfAbsent(f.artifact(), k -> new ArrayList<>()).add(f);
        }
        return report(byArtifact);
    }

    private static int report(Map<String, List<Scanner.Found>> byArtifact) {
        // 🔴 优先级:真的判出了受影响版本(1) > 读不动(4) > 判不了(2) > 没中(0)。发现问题时不降级成 4。
        final boolean unreadable = byArtifact.values().stream().flatMap(List::stream)
                .anyMatch(f -> f.source() != null && f.source().startsWith(Scanner.UNREADABLE_PREFIX));
        System.out.println("async-http-client-check " + VERSION
                + " —— async-http-client " + RuleTable.ADVISORIES + " 条仓库级 advisory 离线自查");
        System.out.println("规则表生成于 " + RuleTable.AS_OF + ":下面的「已收录 / 未收录」是那天 GitHub 全局 advisory 库的状态,"
                + "之后可能已补收。");
        System.out.println("=".repeat(78));

        System.out.println();
        System.out.println("【扫到的构件】");
        for (var e : byArtifact.entrySet()) {
            Set<String> versions = new LinkedHashSet<>();
            for (Scanner.Found f : e.getValue()) versions.add(f.version());
            String mark = Scanner.TARGET.equals(e.getKey()) ? "  ← 本工具判定的就是它" : "";
            System.out.printf("  %-36s %s%s%n", e.getKey(), String.join(", ", versions), mark);
            for (Scanner.Found f : e.getValue()) {
                System.out.printf("      %s%n      └ 证据:%s%n", f.where(), f.source());
            }
        }

        List<Scanner.Found> targets = byArtifact.get(Scanner.TARGET);
        if (targets == null || targets.isEmpty()) {
            System.out.println();
            System.out.println("没有扫到 " + Scanner.GROUP + ":" + Scanner.TARGET + " —— 本工具判不了。");
            if (byArtifact.containsKey(Scanner.LEGACY_GROUP + ":" + Scanner.TARGET)) {
                System.out.println("🔴 扫到的是旧坐标 com.ning:async-http-client(1.x),早已停止维护,本工具不判 —— 不等于安全。");
            }
            return unreadable ? EXIT_UNREADABLE : 2;
        }

        int exit = 0;
        Set<String> allFixes = new LinkedHashSet<>();
        boolean anyUnknown = false;
        for (String v : distinctVersions(targets)) {
            Judge.Verdict verdict = Judge.judge(v);
            System.out.println();
            System.out.println("-".repeat(78));
            System.out.println("【判定】" + Scanner.TARGET + " " + v);

            if (!verdict.judged()) {
                System.out.println("  ⚠️ 判不了:" + verdict.unknownReason());
                anyUnknown = true;
                continue;
            }
            for (String w : verdict.warnings()) System.out.println("  ⚠️ " + w);
            if (verdict.clean()) {
                if (!verdict.warnings().isEmpty()) {
                    // 预发布版一条没中 ≠ 安全,只是 advisory 没写到它
                    System.out.println("  ⚠️ 按 advisory 原文区间一条没中,但见上一行 —— 本工具不把它判成安全。");
                    anyUnknown = true;
                    continue;
                }
                System.out.println("  ✅ 这 " + RuleTable.ADVISORIES + " 条里一条都没中。");
                System.out.println("  🔴 但这只说明这 " + RuleTable.ADVISORIES
                        + " 条(截至 " + RuleTable.AS_OF + ")—— 不是「async-http-client 没有别的问题」。");
                continue;
            }

            exit = 1;
            System.out.println("  🔴 中了 " + verdict.hits().size() + " 条"
                    + (verdict.invisible() > 0
                        ? ",其中 " + verdict.invisible() + " 条 Dependabot / OSV 看不见(GitHub 全局 advisory 库未收录):"
                        : ":"));
            for (RuleTable.Rule r : verdict.hits()) {
                System.out.printf("     %-20s %-8s %s%n", r.id(), r.severity(), r.title());
                System.out.printf("        区间 %s → 修复版 %s · Dependabot/全局库:%s%n",
                        r.range(), r.fix() != null ? r.fix() : "无(" + r.line() + " 线已停止维护)",
                        r.inGlobal() ? "已收录" : "未收录");
            }

            System.out.println();
            if (verdict.migrateTo() != null) {
                // 🔴 命中了「本线无修复版」的条目:本线内不存在干净版本,不许再给一个本线的版本号当答案。
                System.out.println("  🔴 其中 " + verdict.unfixed() + " 条在 " + verdict.line()
                        + " 线上没有修复版。官方原文:");
                System.out.println("     \"" + RuleTable.EOL_QUOTE + "\"");
                if (verdict.fixAll() != null && Versions.compare(verdict.version(), verdict.fixAll()) < 0) {
                    // 🔴 「升完还剩几条」要拿升完的那个版本重新判,不能直接用当前版本的无修复条数 ——
                    // 2.12.3 现在中 4 条无修复的,升到 2.16.1 之后是 5 条(CVE-2026-107229 从 2.16.0 起才中)。
                    System.out.println("  → 留在 " + verdict.line() + " 线最多能升到 " + verdict.fixAll()
                            + ",升完仍中 " + verdict.remainingAfterFixAll() + " 条(都没有修复版)。");
                } else {
                    System.out.println("  → 这已经是 " + verdict.line() + " 线能到的最高修复状态,仍中这 "
                            + verdict.unfixed() + " 条。");
                }
                System.out.println("  → 要修完只能迁到 3.x 线的 " + verdict.migrateTo() + "(跨大版本,不是只改一个版本号)。");
                allFixes.add(verdict.migrateTo() + "(从 " + verdict.line() + " 线迁移)");
            } else {
                allFixes.add(verdict.fixAll());
                System.out.println("  → 一次修完这几条要升到:" + verdict.fixAll());
            }
            if (verdict.invisible() > 0 && verdict.migrateTo() == null) {
                if (verdict.dependabotFix() == null) {
                    System.out.println("  🔴 这几条全局库一条都没收 —— Dependabot / OSV 对这个版本不会报任何东西。");
                } else if (Versions.compare(verdict.dependabotFix(), verdict.fixAll()) < 0) {
                    System.out.println("  🔴 Dependabot / OSV 只看全局库,会叫你升到 " + verdict.dependabotFix()
                            + " —— 升上去之后它显示干净,但 " + verdict.dependabotFix()
                            + " 本身仍落在上面几条「未收录」的区间里,要到 " + verdict.fixAll() + " 才修完。");
                }
            }
        }

        System.out.println();
        System.out.println("=".repeat(78));
        if (!allFixes.isEmpty()) {
            System.out.println("结论:" + Scanner.TARGET + " 需要升到 " + String.join(" / ", allFixes));
        }
        if (exit == 0 && unreadable) return EXIT_UNREADABLE;
        if (anyUnknown && exit == 0) return 2;
        return exit;
    }

    private static List<String> distinctVersions(List<Scanner.Found> found) {
        Map<String, Boolean> seen = new LinkedHashMap<>();
        for (Scanner.Found f : found) seen.put(f.version(), true);
        return new ArrayList<>(seen.keySet());
    }

    private static boolean has(String[] a, String s) { return indexOf(a, s) >= 0; }

    private static int indexOf(String[] a, String s) {
        for (int i = 0; i < a.length; i++) if (a[i].equals(s)) return i;
        return -1;
    }

    private static void usage() {
        System.out.println("async-http-client-check " + VERSION);
        System.out.println("离线判定 org.asynchttpclient:async-http-client 的 " + RuleTable.ADVISORIES + " 条仓库级 advisory");
        System.out.println("(截至 " + RuleTable.AS_OF + " 其中 " + RuleTable.MISSING_GLOBAL
                + " 条 GitHub 全局 advisory 库未收录 —— Dependabot / OSV 看不见;");
        System.out.println(" " + RuleTable.EOL_LINE + " 线官方已停止维护,有 advisory 在该线上没有修复版)。");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java -jar async-http-client-check.jar <目录或 jar/war>");
        System.out.println("  java -jar async-http-client-check.jar --version-of 3.0.13");
        System.out.println();
        System.out.println("退出码:0 = 没中 · 1 = 中了 · 2 = 判不了 · 4 = 有文件读不动");
        System.out.println();
        System.out.println("🔴 只认落地的 jar,刻意不读 pom.xml —— async-http-client 常是被别的库传递带进来的,");
        System.out.println("   pom.xml 里根本不会出现这个 artifactId。");
    }

    private Main() { }
}
