package com.hwlcn.ldap.ldap.sdk.experimental;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DraftBeheraLDAPPasswordPolicy10WarningType
{

  TIME_BEFORE_EXPIRATION("time before expiration"),


  GRACE_LOGINS_REMAINING("grace logins remaining");


  private final String name;


  private DraftBeheraLDAPPasswordPolicy10WarningType(final String name)
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
