package com.hwlcn.security.crypto;

import com.hwlcn.security.util.ByteSource;

public interface RandomNumberGenerator {

    ByteSource nextBytes();

    ByteSource nextBytes(int numBytes);
}
