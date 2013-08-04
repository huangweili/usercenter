
package com.hwlcn.ldap.util;


import com.hwlcn.core.annotation.ThreadSafety;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum OutputFormat
{

  COLUMNS,



  TAB_DELIMITED_TEXT,

  CSV;
}
