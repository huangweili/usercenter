
package com.hwlcn.ldap.ldap.sdk.schema;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ObjectClassType
{

  ABSTRACT("ABSTRACT"),

  STRUCTURAL("STRUCTURAL"),

  AUXILIARY("AUXILIARY");

  private final String name;

  private ObjectClassType(final String name)
  {
    this.name = name;
  }

  public String getName()
  {
    return name;
  }

  @Override()
  public String toString()
  {
    return name;
  }
}
