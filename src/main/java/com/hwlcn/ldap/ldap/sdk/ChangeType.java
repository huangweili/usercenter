package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ChangeType
{

  ADD("add"),

  DELETE("delete"),

  MODIFY("modify"),

  MODIFY_DN("moddn");

  private final String name;

  private ChangeType(final String name)
  {
    this.name = name;
  }

  public String getName()
  {
    return name;
  }

  public static ChangeType forName(final String name)
  {
    final String lowerName = toLowerCase(name);
    if (lowerName.equals("add"))
    {
      return ADD;
    }
    else if (lowerName.equals("delete"))
    {
      return DELETE;
    }
    else if (lowerName.equals("modify"))
    {
      return MODIFY;
    }
    else if (lowerName.equals("moddn") || lowerName.equals("modrdn"))
    {
      return MODIFY_DN;
    }
    else
    {
      return null;
    }
  }

  @Override()
  public String toString()
  {
    return name;
  }
}
