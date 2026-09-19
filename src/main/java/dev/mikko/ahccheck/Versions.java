package dev.mikko.ahccheck;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AsyncHttpClient 版本号解析与比较。
 *
 * <p>后缀形态是从 Central 的 maven-metadata.xml 全量读出来的(2026-09-19),不是猜的:
 * <pre>
 *   2.0.0-alpha13 / 2.0.0-RC1 / 2.1.0-alpha1   (2.x 线:连字符 + 小写 alpha / 大写 RC)
 *   3.0.0.Beta1                                 (3.x 线:点 + Beta)
 * </pre>
 * 两种分隔符、大小写混用 —— <b>全部都得认</b>。
 *
 * <p>🔴 <b>预发布必须排在同号正式版之前。</b> {@code 3.0.0.Beta1} 早于 {@code 3.0.0};
 * 排反了会把仍受影响的版本判成安全 —— 这类错「错得没声音」。
 *
 * <p>🔴 <b>解析不了就返回 null,绝不许当 0 处理。</b> 调用方必须把它当「判不了」上报。
 */
final class Versions {

    private static final Pattern P =
            Pattern.compile("^(\\d+)\\.(\\d+)(?:\\.(\\d+))?(?:[.\\-](.+))?$");

    private static final Pattern STAGE =
            Pattern.compile("^(ALPHA|BETA|M|CR|RC)0*(\\d*)$");

    private static final int ALPHA = 1, BETA = 2, MILESTONE = 3, CANDIDATE = 4, FINAL = 5;

    /** @return {@code [major, minor, patch, stage, stageNum]};解析不了返回 {@code null} */
    static int[] parse(String v) {
        if (v == null) return null;
        Matcher m = P.matcher(v.trim());
        if (!m.matches()) return null;

        int major = Integer.parseInt(m.group(1));
        int minor = Integer.parseInt(m.group(2));
        int patch = m.group(3) == null ? 0 : Integer.parseInt(m.group(3));

        String suffix = m.group(4);
        if (suffix == null || suffix.isEmpty()) return new int[]{major, minor, patch, FINAL, 0};

        String s = suffix.toUpperCase(Locale.ROOT);
        if (s.equals("FINAL") || s.equals("RELEASE") || s.equals("GA")) {
            return new int[]{major, minor, patch, FINAL, 0};
        }
        Matcher st = STAGE.matcher(s);
        if (!st.matches()) return null;   // 认不出的后缀 -> 判不了,不猜

        int stage = switch (st.group(1)) {
            case "ALPHA" -> ALPHA;
            case "BETA"  -> BETA;
            case "M"     -> MILESTONE;
            default      -> CANDIDATE;
        };
        int num = st.group(2).isEmpty() ? 0 : Integer.parseInt(st.group(2));
        return new int[]{major, minor, patch, stage, num};
    }

    /** @throws IllegalArgumentException 任一无法解析时 —— 静默返回 0 会让判定错得没声音 */
    static int compare(String a, String b) {
        int[] x = parse(a), y = parse(b);
        if (x == null || y == null) {
            throw new IllegalArgumentException("无法解析的版本号: " + (x == null ? a : b));
        }
        for (int i = 0; i < x.length; i++) {
            if (x[i] != y[i]) return Integer.compare(x[i], y[i]);
        }
        return 0;
    }

    /** {@code 3.0.12 -> "3.x"};解析不了返回 null。 */
    static String line(String v) {
        int[] p = parse(v);
        return p == null ? null : p[0] + ".x";
    }

    /** 是不是预发布(alpha / Beta / RC ...)。解析不了返回 false —— 那种情况由 line()==null 兜住。 */
    static boolean isPreRelease(String v) {
        int[] p = parse(v);
        return p != null && p[3] != FINAL;
    }

    private Versions() { }
}
