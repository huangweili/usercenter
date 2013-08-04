package com.hwlcn.ldap.ldap.sdk.schema;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum AttributeUsage
{

  USER_APPLICATIONS("userApplications", false),

  DIRECTORY_OPERATION("directoryOperation", true),

  DISTRIBUTED_OPERATION("distributedOperation", true),

  DSA_OPERATION("dSAOperation", true);

  private final boolean isOperational;

  private final String name;

  private AttributeUsage(final String name, final boolean isOperational)
  {
    this.name          = name;
    this.isOperational = isOperational;
  }

  public String getName()
  {
    return name;
  }

  public boolean isOperational()
  {
    return isOperational;
  }

  @Override()
  public String toString()
  {
    return name;
  }
}
