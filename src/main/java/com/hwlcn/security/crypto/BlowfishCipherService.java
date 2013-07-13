package com.hwlcn.security.crypto;
public class BlowfishCipherService extends DefaultBlockCipherService {

    private static final String ALGORITHM_NAME = "Blowfish";
    private static final int BLOCK_SIZE = 64;

    public BlowfishCipherService() {
        super(ALGORITHM_NAME);
        setInitializationVectorSize(BLOCK_SIZE); //like most block ciphers, the IV size is the same as the block size
    }
}
