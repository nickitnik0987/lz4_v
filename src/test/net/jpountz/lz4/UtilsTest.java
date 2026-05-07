package net.jpountz.lz4;

import net.jpountz.util.SafeUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

public class UtilsTest {
  @ParameterizedTest
  @EnumSource
  public void matchRunLength(UtilsImplementation impl) {
    byte[] arr = new byte[1024 * 1024];
    for (int toEncode = 0; toEncode < 1000000; toEncode++) {
      int expected = LZ4Utils.lengthOfEncodedInteger(toEncode);
      int n = toEncode >= 15 ? impl.writeLen(toEncode - 15, arr, 0) : 0;
      int finalToEncode = toEncode;
      assertEquals(expected, n, () -> String.valueOf(finalToEncode));
    }
  }

  @ParameterizedTest
  @EnumSource
  public void encodeSequenceJustRight(UtilsImplementation impl) {
    int runLength = 16;
    byte[] dest = new byte[1 + LZ4Utils.lengthOfEncodedInteger(runLength) + runLength + 2 + (1 + LZ4Constants.LAST_LITERALS)];
    impl.encodeSequence(
      new byte[runLength],
      0,
      runLength,
      0,
      0,
      dest,
      0,
      dest.length
    );
  }

  @Test
  public void notEnoughSpace() {
    assertTrue(LZ4Utils.notEnoughSpace(0, 1));
    assertTrue(LZ4Utils.notEnoughSpace(3, Integer.MAX_VALUE));
    assertTrue(LZ4Utils.notEnoughSpace(3, -1));
    assertTrue(LZ4Utils.notEnoughSpace(0, -1));
    assertTrue(LZ4Utils.notEnoughSpace(-1, 3));
    assertTrue(LZ4Utils.notEnoughSpace(-1, 0));
    assertTrue(LZ4Utils.notEnoughSpace(-1, -1));

    assertFalse(LZ4Utils.notEnoughSpace(0, 0));
    assertFalse(LZ4Utils.notEnoughSpace(7, 5));
    assertFalse(LZ4Utils.notEnoughSpace(7, 7));
  }

  public enum UtilsImplementation {
    SAFE {
      @Override
      int writeLen(int len, byte[] dest, int dOff) {
        return LZ4SafeUtils.writeLen(len, dest, dOff);
      }

      @Override
      int encodeSequence(byte[] src, int anchor, int matchOff, int matchRef, int matchLen, byte[] dest, int dOff, int destEnd) {
        return LZ4SafeUtils.encodeSequence(src, anchor, matchOff, matchRef, matchLen, dest, dOff, destEnd);
      }
    },
    UNSAFE {
      @Override
      int writeLen(int len, byte[] dest, int dOff) {
        return LZ4UnsafeUtils.writeLen(len, dest, dOff);
      }

      @Override
      int encodeSequence(byte[] src, int anchor, int matchOff, int matchRef, int matchLen, byte[] dest, int dOff, int destEnd) {
        return LZ4UnsafeUtils.encodeSequence(src, anchor, matchOff, matchRef, matchLen, dest, dOff, destEnd);
      }
    },
    BYTE_BUFFER {
      @Override
      int writeLen(int len, byte[] dest, int dOff) {
        return LZ4ByteBufferUtils.writeLen(len, ByteBuffer.wrap(dest), dOff);
      }

      @Override
      int encodeSequence(byte[] src, int anchor, int matchOff, int matchRef, int matchLen, byte[] dest, int dOff, int destEnd) {
        return LZ4ByteBufferUtils.encodeSequence(ByteBuffer.wrap(src), anchor, matchOff, matchRef, matchLen, ByteBuffer.wrap(dest), dOff, destEnd);
      }
    };

    abstract int writeLen(int len, byte[] dest, int dOff);

    abstract int encodeSequence(byte[] src, int anchor, int matchOff, int matchRef, int matchLen, byte[] dest, int dOff, int destEnd);
  }
}
