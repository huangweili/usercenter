
package com.hwlcn.security.crypto.hash.format;

import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.crypto.hash.SimpleHash;
import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.crypto.hash.Hash;
import com.hwlcn.security.util.StringUtils;

public class SecurityCryptFormat implements ModularCryptFormat, ParsableHashFormat {

    public static final String ID = "security";
    public static final String MCF_PREFIX = TOKEN_DELIMITER + ID + TOKEN_DELIMITER;

    public SecurityCryptFormat() {
    }

    public String getId() {
        return ID;
    }

    public String format(Hash hash) {
        if (hash == null) {
            return null;
        }

        String algorithmName = hash.getAlgorithmName();
        ByteSource salt = hash.getSalt();
        int iterations = hash.getIterations();
        StringBuilder sb = new StringBuilder(MCF_PREFIX).append(algorithmName).append(TOKEN_DELIMITER).append(iterations).append(TOKEN_DELIMITER);

        if (salt != null) {
            sb.append(salt.toBase64());
        }

        sb.append(TOKEN_DELIMITER);
        sb.append(hash.toBase64());

        return sb.toString();
    }

    public Hash parse(String formatted) {
        if (formatted == null) {
            return null;
        }
        if (!formatted.startsWith(MCF_PREFIX)) {
            //TODO create a HashFormatException class
            String msg = "The argument is not a valid '" + ID + "' formatted hash.";
            throw new IllegalArgumentException(msg);
        }

        String suffix = formatted.substring(MCF_PREFIX.length());
        String[] parts = suffix.split("\\$");


        int i = parts.length-1;
        String digestBase64 = parts[i--];

        String saltBase64 = parts[i--];
        String iterationsString = parts[i--];
        String algorithmName = parts[i];

        byte[] digest = Base64.decode(digestBase64);
        ByteSource salt = null;

        if (StringUtils.hasLength(saltBase64)) {
            byte[] saltBytes = Base64.decode(saltBase64);
            salt = ByteSource.Util.bytes(saltBytes);
        }

        int iterations;
        try {
            iterations = Integer.parseInt(iterationsString);
        } catch (NumberFormatException e) {
            String msg = "Unable to parse formatted hash string: " + formatted;
            throw new IllegalArgumentException(msg, e);
        }

        SimpleHash hash = new SimpleHash(algorithmName);
        hash.setBytes(digest);
        if (salt != null) {
            hash.setSalt(salt);
        }
        hash.setIterations(iterations);

        return hash;
    }
}
