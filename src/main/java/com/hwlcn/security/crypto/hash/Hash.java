package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.util.ByteSource;


public interface Hash extends ByteSource {

    String getAlgorithmName();


    ByteSource getSalt();

    int getIterations();

}
