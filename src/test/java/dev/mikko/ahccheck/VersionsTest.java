package dev.mikko.ahccheck;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VersionsTest {

    @Test
    void 预发布排在同号正式版之前() {
        assertTrue(Versions.compare("3.0.0.Beta1", "3.0.0") < 0);
        assertTrue(Versions.compare("3.0.0.Beta3", "3.0.0") < 0);
        assertTrue(Versions.compare("2.0.0-alpha27", "2.0.0-RC1") < 0);
        assertTrue(Versions.compare("2.0.0-RC21", "2.0.0") < 0);
        assertTrue(Versions.compare("2.1.0-alpha26", "2.1.0-RC1") < 0);
    }

    @Test
    void 数字段按数值比不按字典序() {
        assertTrue(Versions.compare("3.0.9", "3.0.10") < 0);
        assertTrue(Versions.compare("2.2.0", "2.16.0") < 0);
        assertTrue(Versions.compare("2.0.0-RC2", "2.0.0-RC10") < 0);
    }

    @Test
    void 解析不了返回null而不是0() {
        assertNull(Versions.parse("abc"));
        assertNull(Versions.parse(null));
        assertNull(Versions.parse("3.0.12-SNAPSHOT-foo"));
        assertThrows(IllegalArgumentException.class, () -> Versions.compare("abc", "3.0.0"));
    }

    @Test
    void 版本线() {
        assertEquals("3.x", Versions.line("3.0.12"));
        assertEquals("2.x", Versions.line("2.0.0-alpha13"));
        assertNull(Versions.line("abc"));
    }
}
