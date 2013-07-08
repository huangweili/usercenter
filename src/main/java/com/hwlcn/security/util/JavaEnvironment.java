package com.hwlcn.security.util;

public abstract class JavaEnvironment {

    public static final int JAVA_13 = 0;

    public static final int JAVA_14 = 1;

    public static final int JAVA_15 = 2;

    public static final int JAVA_16 = 3;

    public static final int JAVA_17 = 4;

    public static final int JAVA_18 = 5;

    private static final String version;

    private static final int majorVersion;

    static {
        version = System.getProperty("java.version");
        if (version.indexOf("1.8.") != -1) {
            majorVersion = JAVA_18;
        } else if (version.indexOf("1.7.") != -1) {
            majorVersion = JAVA_17;
        } else if (version.indexOf("1.6.") != -1) {
            majorVersion = JAVA_16;
        } else if (version.indexOf("1.5.") != -1) {
            majorVersion = JAVA_15;
        } else if (version.indexOf("1.4.") != -1) {
            majorVersion = JAVA_14;
        } else {
            majorVersion = JAVA_13;
        }
    }

    public static String getVersion() {
        return version;
    }

    public static int getMajorVersion() {
        return majorVersion;
    }

    public static boolean isAtLeastVersion14() {
        return getMajorVersion() >= JAVA_14;
    }

    public static boolean isAtLeastVersion15() {
        return getMajorVersion() >= JAVA_15;
    }

    public static boolean isAtLeastVersion16() {
        return getMajorVersion() >= JAVA_16;
    }
}
