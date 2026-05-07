package net.jpountz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;

import java.nio.ByteBuffer;

public class XXHash64Test {
  private static final int MAX_LEN = 1 << 16;

  private void testArray(FuzzedDataProvider data, XXHash64 hasher) {
    int srcOff = data.consumeInt(0, 16);
    int srcOffEnd = data.consumeInt(0, 16);
    int requestedLen = data.consumeInt(0, MAX_LEN);
    long seed = data.consumeLong();
    byte[] content = data.consumeRemainingAsBytes();
    int srcLen = Math.min(requestedLen, content.length);

    byte[] src = new byte[srcOff + srcLen + srcOffEnd];
    if (srcLen > 0) {
      System.arraycopy(content, 0, src, srcOff, srcLen);
    }

    // Hash the slice; should not throw for valid bounds.
    hasher.hash(src, srcOff, srcLen, seed);
  }

  private void testByteBuffer(FuzzedDataProvider data, XXHash64 hasher) {
    int srcOff = data.consumeInt(0, 16);
    int srcOffEnd = data.consumeInt(0, 16);
    int requestedLen = data.consumeInt(0, MAX_LEN);
    long seed = data.consumeLong();
    byte[] content = data.consumeRemainingAsBytes();
    int srcLen = Math.min(requestedLen, content.length);

    ByteBuffer srcBuf = ByteBuffer.allocateDirect(srcOff + srcLen + srcOffEnd);
    if (srcLen > 0) {
      srcBuf.position(srcOff);
      srcBuf.put(content, 0, srcLen);
      srcBuf.position(0);
      srcBuf.limit(srcOff + srcLen + srcOffEnd);
    }

    // Hash the slice; ByteBuffer position/limit remain unchanged by this overload.
    hasher.hash(srcBuf, srcOff, srcLen, seed);
  }

  // array-based hashing
  @FuzzTest
  public void safe_array(FuzzedDataProvider provider) {
    testArray(provider, XXHashFactory.safeInstance().hash64());
  }

  @FuzzTest
  public void unsafe_array(FuzzedDataProvider provider) {
    testArray(provider, XXHashFactory.unsafeInstance().hash64());
  }

  @FuzzTest
  public void native_array(FuzzedDataProvider provider) {
    testArray(provider, XXHashFactory.nativeInstance().hash64());
  }

  // direct ByteBuffer-based hashing
  @FuzzTest
  public void safe_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, XXHashFactory.safeInstance().hash64());
  }

  @FuzzTest
  public void unsafe_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, XXHashFactory.unsafeInstance().hash64());
  }

  @FuzzTest
  public void native_bytebuffer(FuzzedDataProvider provider) {
    testByteBuffer(provider, XXHashFactory.nativeInstance().hash64());
  }
}
