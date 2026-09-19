package dev.mikko.ahccheck;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RangesTest {

    @Test
    void 实际出现的写法都认得() {
        assertTrue(Ranges.contains(">= 3.0.0, <= 3.0.12", "3.0.12"));
        assertFalse(Ranges.contains(">= 3.0.0, <= 3.0.12", "3.0.13"));

        assertTrue(Ranges.contains(">= 3.0.0.Beta1, < 3.0.11", "3.0.10"));
        assertFalse(Ranges.contains(">= 3.0.0.Beta1, < 3.0.11", "3.0.11"));
        assertTrue(Ranges.contains(">= 3.0.0.Beta1, < 3.0.11", "3.0.0.Beta1"));

        assertTrue(Ranges.contains("= 3.0.12", "3.0.12"));
        assertFalse(Ranges.contains("= 3.0.12", "3.0.11"));

        assertTrue(Ranges.contains("3.0.0", "3.0.0"));          // 裸版本号 = 精确等于
        assertFalse(Ranges.contains("3.0.0", "3.0.1"));
        assertFalse(Ranges.contains("3.0.0", "3.0.0.Beta1"));
    }

    @Test
    void 边界_同一个版本对小于与小于等于判定相反() {
        // ⭐ 统一成严格小于会漏报,统一成小于等于会误报
        assertFalse(Ranges.contains(">= 3.0.0.Beta1, < 3.0.11", "3.0.11"));
        assertTrue(Ranges.contains(">= 3.0.0, <= 3.0.11", "3.0.11"));
    }

    @Test
    void 只有下界与大于也认得() {
        assertTrue(Ranges.contains(">= 3.0.0", "3.0.99"));
        assertFalse(Ranges.contains("> 3.0.0", "3.0.0"));
    }

    @Test
    void 下界是正式版时预发布落在区间外() {
        assertFalse(Ranges.contains(">= 3.0.0, <= 3.0.11", "3.0.0.Beta3"));
        assertFalse(Ranges.contains(">= 2.0.0, <= 2.16.0", "2.0.0-RC21"));
    }

    @Test
    void 认不出的写法抛异常而不是当安全() {
        assertThrows(IllegalArgumentException.class, () -> Ranges.contains("大概是 3.0 吧", "3.0.0"));
        assertThrows(IllegalArgumentException.class, () -> Ranges.contains("~> 3.0.0", "3.0.0"));
        assertThrows(IllegalArgumentException.class, () -> Ranges.contains(">= 3.0.0,", "3.0.0"));
        assertThrows(IllegalArgumentException.class, () -> Ranges.contains("", "3.0.0"));
        assertThrows(IllegalArgumentException.class, () -> Ranges.contains(null, "3.0.0"));
    }
}
