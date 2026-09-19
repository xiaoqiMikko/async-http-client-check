package dev.mikko.ahccheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 退出码 4 =「有文件读不动」。
 *
 * <p>🔴 由来(2026-09-09):在此之前,读不动的文件只在 stdout 留一行提示,退出码照旧。
 * 留痕是给人看的,**而 CI / 脚本看的是退出码** —— 于是「我没能读它」在自动化里仍然等于「通过」。
 * 本测试锁住的就是这件事:坏文件必须让退出码变成 4,合法的空 jar 必须不变。
 */
class UnreadableExitCodeTest {

    @Test
    void 不是zip的文件必须让退出码变成4(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("notzip.jar");
        Files.write(f, "this is not a zip at all".getBytes("UTF-8"));

        assertEquals(Main.EXIT_UNREADABLE, Main.run(new String[] {f.toString()}),
                "根本不是 zip 的文件,退出码必须是 4");
    }

    @Test
    void 魔数对但截断的文件也必须让退出码变成4(@TempDir Path dir) throws IOException {
        // 以 PK 加 0x03 0x04 开头 —— 魔数是对的,ZipInputStream 不抛异常,只是零条目。
        // 用字节数组而不是字符串转义:写成转义时会被 shell 吃掉一层,落地成没有魔数的普通文本,
        // 于是这个测试会退化成上一个 —— 照样绿,但守的不是它声称要守的东西。
        byte[] truncated = new byte[] {'P', 'K', 3, 4, ' ', 'n', 'o', 't', ' ', 'a', ' ', 'z', 'i', 'p'};
        Path f = dir.resolve("truncated.jar");
        Files.write(f, truncated);

        assertEquals(Main.EXIT_UNREADABLE, Main.run(new String[] {f.toString()}),
                "魔数对但内容截断的文件,退出码必须是 4");
    }

    @Test
    void 合法的空jar不许被当成读不动(@TempDir Path dir) throws IOException {
        // 一条 22 字节的 EOCD 记录 —— 这是一个真的空 zip,不是坏文件。
        byte[] emptyZip = new byte[22];
        emptyZip[0] = 'P';
        emptyZip[1] = 'K';
        emptyZip[2] = 5;
        emptyZip[3] = 6;
        Path f = dir.resolve("empty.jar");
        Files.write(f, emptyZip);

        assertNotEquals(Main.EXIT_UNREADABLE, Main.run(new String[] {f.toString()}),
                "合法的空 jar 不是坏文件 —— 假告警多了,真告警就没人看");
    }
}
