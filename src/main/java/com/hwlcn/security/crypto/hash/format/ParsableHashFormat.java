
package com.hwlcn.security.crypto.hash.format;

import com.hwlcn.security.crypto.hash.Hash;


public interface ParsableHashFormat extends HashFormat {

    Hash parse(String formatted);
}
