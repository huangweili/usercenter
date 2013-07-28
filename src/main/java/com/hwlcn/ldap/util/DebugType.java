
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;

import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DebugType
{

  ASN1("asn1"),



  CONNECT("connect"),



  EXCEPTION("exception"),



  LDAP("ldap"),


  LDIF("ldif"),




  MONITOR("monitor"),



  CODING_ERROR("coding-error"),



  OTHER("other");



  private final String name;



  private DebugType(final String name)
  {
    this.name = name;
  }




  public String getName()
  {
    return name;
  }




  public static DebugType forName(final String name)
  {
    final String lowerName = toLowerCase(name);

    if (lowerName.equals("asn1"))
    {
      return ASN1;
    }
    else if (lowerName.equals("connect"))
    {
      return CONNECT;
    }
    else if (lowerName.equals("exception"))
    {
      return EXCEPTION;
    }
    else if (lowerName.equals("ldap"))
    {
      return LDAP;
    }
    else if (lowerName.equals("ldif"))
    {
      return LDIF;
    }
    else if (lowerName.equals("monitor"))
    {
      return MONITOR;
    }
    else if (lowerName.equals("coding-error"))
    {
      return CODING_ERROR;
    }
    else if (lowerName.equals("other"))
    {
      return OTHER;
    }

    return null;
  }




  public static String getTypeNameList()
  {
    final StringBuilder buffer = new StringBuilder();

    final DebugType[] types = DebugType.values();
    for (int i=0; i < types.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(types[i].getName());
    }

    return buffer.toString();
  }



  @Override()
  public String toString()
  {
    return name;
  }
}
