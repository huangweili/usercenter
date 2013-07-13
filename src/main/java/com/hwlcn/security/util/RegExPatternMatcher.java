package com.hwlcn.security.util;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RegExPatternMatcher implements PatternMatcher {


    public boolean matches(String pattern, String source) {
        if (pattern == null) {
            throw new IllegalArgumentException("pattern argument cannot be null.");
        }
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(source);
        return m.matches();
    }
}
