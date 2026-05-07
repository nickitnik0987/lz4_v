package net.jpountz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;

import java.nio.ByteBuffer;

public class LZ4CompressorTest {
  private static final int MAX_LEN = 1 << 16;

  private void testArray(FuzzedDataProvider data, LZ4Compressor compressor) {
    int destOff = data.consumeInt(0, 16);
    int maxDestLen = data.consumeInt(0, MAX_LEN);
    int srcOff = data.consumeInt(0, 16);
    int srcOffEnd = data.consumeInt(0, 16);
    int requestedSrcLen = data.consumeInt(0, MAX_LEN);
    byte[] content = data.consumeRemainingAsBytes();
    int srcLen = Math.min(requestedSrcLen, content.length);

    byte[] src = new byte[srcOff + srcLen + srcOffEnd];
    if (srcLen > 0) {
      System.arraycopy(content, 0, src, srcOff, srcLen);
    }
    byte[] dest = new byte[destOff + maxDestLen];

    try {
      compressor.compress(src, srcOff, srcLen, dest, destOff, maxDestLen);
    } catch (LZ4Exception ignored) {
    }
  }

  private void testByteBuffer(FuzzedDataProvider data, LZ4Compressor compressor) {
    int destOff = data.consumeInt(0, 16);
    int maxDestLen = data.consumeInt(0, MAX_LEN);
    int srcOff = data.consumeInt(0, 16);
    int srcOffEnd = data.consumeInt(0, 16);
    int requestedSrcLen = data.consumeInt(0, MAX_LEN);
    byte[] content = data.consumeRemainingAsBytes();
    int srcLen = Math.min(requestedSrcLen, content.length);

    ByteBuffer srcBuf = ByteBuffer.allocateDirect(srcOff + srcLen + srcOffEnd);
    if (srcLen > 0) {
      srcBuf.position(srcOff);
      srcBuf.put(content, 0, srcLen);
    }
    ByteBuffer destBuf = ByteBuffer.allocateDirect(destOff + maxDestLen);

    try {
      compressor.compress(srcBuf, srcOff, srcLen, destBuf, destOff, maxDestLen);
    } catch (LZ4Exception ignored) {
    }
  }

  // fastCompressor: array
  @FuzzTest
  public void safe_fast_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.safeInstance().fastCompressor());
  }

  @FuzzTest
  public void unsafe_fast_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.unsafeInsecureInstance().fastCompressor());
  }

  @FuzzTest
  public void native_fast_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.nativeInsecureInstance().fastCompressor());
  }

  // fastCompressor: bytebuffer
  @FuzzTest
  public void safe_fast_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.safeInstance().fastCompressor());
  }

  @FuzzTest
  public void unsafe_fast_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.unsafeInsecureInstance().fastCompressor());
  }

  @FuzzTest
  public void native_fast_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.nativeInsecureInstance().fastCompressor());
  }

  // highCompressor (levels 1, 9 (default), 17 (max)): array
  @FuzzTest
  public void safe_high_l1_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.safeInstance().highCompressor(1));
  }

  @FuzzTest
  public void unsafe_high_l1_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(1));
  }

  @FuzzTest
  public void native_high_l1_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.nativeInsecureInstance().highCompressor(1));
  }

  @FuzzTest
  public void safe_high_l9_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.safeInstance().highCompressor(9));
  }

  @FuzzTest
  public void unsafe_high_l9_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(9));
  }

  @FuzzTest
  public void native_high_l9_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.nativeInsecureInstance().highCompressor(9));
  }

  @FuzzTest
  public void safe_high_l17_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.safeInstance().highCompressor(17));
  }

  @FuzzTest
  public void unsafe_high_l17_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(17));
  }

  @FuzzTest
  public void native_high_l17_array(FuzzedDataProvider provider) {
    testArray(provider, LZ4Factory.nativeInsecureInstance().highCompressor(17));
  }

  // highCompressor (levels 1, 9, 17): bytebuffer
  @FuzzTest
  public void safe_high_l1_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.safeInstance().highCompressor(1));
  }

  @FuzzTest
  public void unsafe_high_l1_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(1));
  }

  @FuzzTest
  public void native_high_l1_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.nativeInsecureInstance().highCompressor(1));
  }

  @FuzzTest
  public void safe_high_l9_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.safeInstance().highCompressor(9));
  }

  @FuzzTest
  public void unsafe_high_l9_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(9));
  }

  @FuzzTest
  public void native_high_l9_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.nativeInsecureInstance().highCompressor(9));
  }

  @FuzzTest
  public void safe_high_l17_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.safeInstance().highCompressor(17));
  }

  @FuzzTest
  public void unsafe_high_l17_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.unsafeInsecureInstance().highCompressor(17));
  }

  @FuzzTest
  public void native_high_l17_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, LZ4Factory.nativeInsecureInstance().highCompressor(17));
  }
}
