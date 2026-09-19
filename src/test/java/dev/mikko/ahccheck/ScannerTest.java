package dev.mikko.ahccheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ScannerTest {

    static byte[] zip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            for (var e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    /** 与 Central 上 3.0.12 真 jar 同样的 pom.properties 路径(2026-09-19 拆过)。 */
    static byte[] ahcJar(String group, String artifact, String version) throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("META-INF/maven/" + group + "/" + artifact + "/pom.properties",
                ("artifactId=" + artifact + "\ngroupId=" + group + "\nversion=" + version + "\n")
                        .getBytes(StandardCharsets.UTF_8));
        m.put("org/asynchttpclient/AsyncHttpClient.class", new byte[]{1, 2, 3});
        return zip(m);
    }

    private static List<Scanner.Found> of(List<Scanner.Found> all, String artifact) {
        return all.stream().filter(f -> f.artifact().equals(artifact)).toList();
    }

    @Test
    void 从pom_properties读出版本_且不靠文件名(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("renamed.jar"), ahcJar("org.asynchttpclient", "async-http-client", "3.0.12"));

        List<Scanner.Found> found = of(Scanner.scan(dir), Scanner.TARGET);
        assertEquals(1, found.size());
        assertEquals("3.0.12", found.get(0).version());
        assertTrue(found.get(0).source().contains("pom.properties"));
    }

    @Test
    void 旧坐标com_ning不当成新坐标判(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("a.jar"), ahcJar("com.ning", "async-http-client", "1.9.40"));

        List<Scanner.Found> all = Scanner.scan(dir);
        assertTrue(of(all, Scanner.TARGET).isEmpty(), "com.ning 的同名 artifactId 不许被判成新坐标");
        assertEquals(1, of(all, "com.ning:async-http-client").size());
    }

    @Test
    void 同组其它构件单独列出不参与判定(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("a.jar"), ahcJar("org.asynchttpclient", "async-http-client", "2.12.3"));
        Files.write(dir.resolve("b.jar"), ahcJar("org.asynchttpclient", "async-http-client-netty-utils", "2.12.3"));

        List<Scanner.Found> all = Scanner.scan(dir);
        assertEquals(1, of(all, Scanner.TARGET).size());
        assertEquals(1, of(all, "async-http-client-netty-utils").size());
    }

    @Test
    void fat_jar与war里的嵌套jar都能认出(@TempDir Path dir) throws Exception {
        Map<String, byte[]> fat = new LinkedHashMap<>();
        fat.put("BOOT-INF/lib/lib-a.jar", ahcJar("org.asynchttpclient", "async-http-client", "3.0.11"));
        fat.put("BOOT-INF/classes/App.class", new byte[]{9});
        Files.write(dir.resolve("app.jar"), zip(fat));

        Map<String, byte[]> war = new LinkedHashMap<>();
        war.put("WEB-INF/lib/x.jar", ahcJar("org.asynchttpclient", "async-http-client", "2.16.0"));
        Files.write(dir.resolve("app.war"), zip(war));

        List<Scanner.Found> t = of(Scanner.scan(dir), Scanner.TARGET);
        assertEquals(2, t.size());
        assertTrue(t.stream().anyMatch(f -> f.version().equals("3.0.11") && f.where().contains("!/BOOT-INF/lib/lib-a.jar")));
        assertTrue(t.stream().anyMatch(f -> f.version().equals("2.16.0") && f.where().contains("!/WEB-INF/lib/x.jar")));
    }

    @Test
    void 文件名兜底_但标成弱证据(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("async-http-client-2.12.3.jar"), zip(Map.of("a/B.class", new byte[]{1})));
        Files.write(dir.resolve("async-http-client-netty-utils-2.12.3.jar"), zip(Map.of("a/C.class", new byte[]{1})));

        List<Scanner.Found> all = Scanner.scan(dir);
        List<Scanner.Found> found = of(all, Scanner.TARGET);
        assertEquals(1, found.size(), "netty-utils 的文件名不许被切成 async-http-client:" + all);
        assertEquals("2.12.3", found.get(0).version());
        assertTrue(found.get(0).source().contains("弱证据"));
    }

    @Test
    void 读不动的文件报出来而不是当成里面没有(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("broken.jar"), "这不是一个 zip".getBytes(StandardCharsets.UTF_8));
        assertTrue(Scanner.scan(dir).stream().anyMatch(f -> f.source().startsWith(Scanner.UNREADABLE_PREFIX)));
    }

    @Test
    void 空的jar是合法的_不许报成读取失败(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("empty.jar"), zip(Map.of()));
        assertTrue(Scanner.scan(dir).stream().noneMatch(f -> f.source().startsWith(Scanner.UNREADABLE_PREFIX)));
    }

    @Test
    void 魔数对但内容截断的也要报出来(@TempDir Path dir) throws Exception {
        byte[] truncated = new byte[]{'P', 'K', 3, 4, ' ', 'n', 'o', 't', ' ', 'a', ' ', 'z', 'i', 'p'};
        assertTrue(truncated[2] == 3 && truncated[3] == 4, "样本必须带正确的 zip 魔数,否则测的是第一层防线");
        Files.write(dir.resolve("truncated.jar"), truncated);
        assertTrue(Scanner.scan(dir).stream().anyMatch(f -> f.source().startsWith(Scanner.UNREADABLE_PREFIX)));
    }

    // ------------------------------------------------------------------
    // 退出码优先级:中了(1) > 读不动(4) > 没中(0)
    // ------------------------------------------------------------------

    @Test
    void 干净的jar加一个坏文件_退出码是4不是0(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("ok.jar"), ahcJar("org.asynchttpclient", "async-http-client", "3.0.13"));
        Files.write(dir.resolve("broken.jar"), "not a zip".getBytes(StandardCharsets.UTF_8));
        assertEquals(Main.EXIT_UNREADABLE, Main.run(new String[]{dir.toString()}));
    }

    @Test
    void 中招的jar加一个坏文件_退出码是1不降级(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("bad.jar"), ahcJar("org.asynchttpclient", "async-http-client", "3.0.12"));
        Files.write(dir.resolve("broken.jar"), "not a zip".getBytes(StandardCharsets.UTF_8));
        assertEquals(1, Main.run(new String[]{dir.toString()}));
    }

    @Test
    void 干净的jar_退出码0(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("ok.jar"), ahcJar("org.asynchttpclient", "async-http-client", "2.16.1"));
        assertEquals(0, Main.run(new String[]{dir.toString()}));
    }

    @Test
    void 预发布版一条没中也不判成干净(@TempDir Path dir) throws Exception {
        assertNotEquals(0, Main.run(new String[]{"--version-of", "2.0.0-RC1"}));
    }
}
