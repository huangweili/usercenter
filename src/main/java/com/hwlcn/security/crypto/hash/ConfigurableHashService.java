package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.crypto.RandomNumberGenerator;
import com.hwlcn.security.util.ByteSource;

public interface ConfigurableHashService extends HashService {

    void setPrivateSalt(ByteSource privateSalt);

    void setHashIterations(int iterations);

    void setHashAlgorithmName(String name);

    void setRandomNumberGenerator(RandomNumberGenerator rng);
}
