package dev.mikko.ahccheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 找出实际装着的 async-http-client 与版本。
 *
 * <p>🔴 <b>刻意不扫 pom.xml</b>:AHC 很少被直接声明,常见是被别的库传递带进来的
 * (各家 SDK、HTTP 客户端封装、测试工具)。照 pom 判会得出「我没用它」这个错误结论。所以只认落地的 jar。
 *
 * <p>两个来源,按可信度排:
 * <ol>
 *   <li>jar 内 {@code META-INF/maven/org.asynchttpclient/<artifact>/pom.properties} ——
 *       最硬(2026-09-19 拆 Central 上的 3.0.12 真 jar 确认有这个文件)</li>
 *   <li>文件名 {@code async-http-client-<ver>.jar} —— 最弱,能被改名骗到</li>
 * </ol>
 *
 * <p>🔴 <b>groupId 必须核</b>:1.x 时代的旧坐标 {@code com.ning:async-http-client} 与新坐标 artifactId 同名。
 * 不核 groupId 会把 1.x 当成新坐标去判。旧坐标会被列出来,但不参与判定。
 */
final class Scanner {

    /** 一个发现。artifact 对新坐标是裸 artifactId,对其它 groupId 是 {@code group:artifact}。 */
    record Found(String artifact, String version, String where, String source) { }

    /**
     * 「这个文件读不动」的证据前缀。
     *
     * <p>🔴 判据要和措辞绑在同一个符号上 —— {@code Main} 靠这个前缀把退出码抬到 4;
     * 若措辞被改而判据还在匹配旧字符串,「读不动」会重新变回一个安静的 0。
     */
    static final String UNREADABLE_PREFIX = "读取失败: ";

    static final String GROUP = "org.asynchttpclient";

    /** 本工具出判定的那个构件。 */
    static final String TARGET = "async-http-client";

    /** 旧坐标的 groupId。列出来但不判。 */
    static final String LEGACY_GROUP = "com.ning";

    /** org.asynchttpclient 下的构件(async-http-client / -netty-utils / -extras-* 等)。 */
    private static final Pattern ARTIFACT = Pattern.compile("^async-http-client(-[a-z][\\w\\-]*)?$");

    private static final Pattern FILENAME =
            Pattern.compile("^(async-http-client(?:-[a-z][\\w\\-]*?)?)-(\\d[\\w.\\-]*)\\.jar$");

    /** 嵌套 jar 的最大深度 —— 防的是环。 */
    private static final int MAX_DEPTH = 3;

    static List<Found> scan(Path root) throws IOException {
        List<Found> out = new ArrayList<>();
        if (Files.isDirectory(root)) {
            try (var s = Files.walk(root)) {
                for (Path p : s.filter(Files::isRegularFile).toList()) {
                    String n = p.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                        scanArchive(read(p), p.toString(), out, 0);
                    }
                }
            }
        } else if (Files.isRegularFile(root)) {
            scanArchive(read(root), root.toString(), out, 0);
        }
        return out;
    }

    /** 读文件本身失败(权限、占用)也是「读不动」,不许抛出去让整个扫描判不了、也不许吞掉。 */
    private static byte[] read(Path p) {
        try {
            return Files.readAllBytes(p);
        } catch (IOException e) {
            return null;
        }
    }

    /** 合法的空 zip —— 整个文件就是一条 22 字节的 EOCD 记录。它是真的空,不该报错。 */
    private static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') return false;
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>(第 10 注实证)。
     * 所以先验魔数;魔数对但零条目(截断)再报一次。两层缺一不可。
     */
    private static void scanArchive(byte[] bytes, String where, List<Found> out, int depth) {
        if (depth > MAX_DEPTH) return;

        if (bytes == null) {
            out.add(new Found("?", "?", where, UNREADABLE_PREFIX + "文件本身读不出来(权限或被占用)"));
            return;
        }
        if (!looksLikeZip(bytes)) {
            // 🔴 说读不动,不说「里面没有」。这两句话会把用户推向相反的动作。
            out.add(new Found("?", "?", where, UNREADABLE_PREFIX + "不是一个可读的 zip/jar(前 4 字节不是 zip 魔数)"));
            return;
        }

        String byNameArtifact = null, byNameVersion = null;
        String base = where.substring(Math.max(where.lastIndexOf('/'), where.lastIndexOf('\\')) + 1);
        Matcher fm = FILENAME.matcher(base);
        if (fm.matches()) {
            byNameArtifact = fm.group(1);
            byNameVersion = fm.group(2);
        }

        boolean gotStrong = false;
        int entries = 0;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                entries++;
                String name = e.getName();

                if (name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties")) {
                    Properties p = load(zin);
                    String g = p.getProperty("groupId"), a = p.getProperty("artifactId"), v = p.getProperty("version");
                    if (g != null && a != null && v != null && ARTIFACT.matcher(a).matches()) {
                        if (GROUP.equals(g)) {
                            out.add(new Found(a, v, where, "META-INF/maven pom.properties"));
                            gotStrong = true;
                        } else if (LEGACY_GROUP.equals(g)) {
                            out.add(new Found(g + ":" + a, v, where, "META-INF/maven pom.properties(旧坐标)"));
                            gotStrong = true;
                        }
                    }
                    continue;
                }

                // 嵌套 jar(Spring Boot fat-jar: BOOT-INF/lib/*.jar;WAR: WEB-INF/lib/*.jar)
                if (name.toLowerCase().endsWith(".jar")) {
                    byte[] inner = zin.readAllBytes();
                    if (inner.length > 0) scanArchive(inner, where + "!/" + name, out, depth + 1);
                }
            }
        } catch (IOException | IllegalArgumentException ex) {
            // 🔴 读不动就说读不动,不许当「里面没有」
            out.add(new Found("?", "?", where, UNREADABLE_PREFIX + ex.getMessage()));
            return;
        }

        if (entries == 0 && !isEmptyZip(bytes)) {
            out.add(new Found("?", "?", where,
                    UNREADABLE_PREFIX + "魔数像 zip,但一个条目都解不出来(多半是截断或下载不全)"));
            return;
        }

        if (!gotStrong && byNameArtifact != null) {
            out.add(new Found(byNameArtifact, byNameVersion, where, "文件名(弱证据,可被改名骗到;也分不出新旧坐标)"));
        }
    }

    private static Properties load(InputStream in) throws IOException {
        Properties p = new Properties();
        p.load(new ByteArrayInputStream(in.readAllBytes()));
        return p;
    }

    private Scanner() { }
}
