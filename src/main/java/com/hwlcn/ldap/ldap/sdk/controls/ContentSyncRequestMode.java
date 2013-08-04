
package com.hwlcn.ldap.ldap.sdk.controls;


public enum ContentSyncRequestMode
{

  REFRESH_ONLY(1),

  REFRESH_AND_PERSIST(3);

  private final int intValue;

  private ContentSyncRequestMode(final int intValue)
  {
    this.intValue = intValue;
  }

  public int intValue()
  {
    return intValue;
  }


  public static ContentSyncRequestMode valueOf(final int intValue)
  {
    if (intValue == REFRESH_ONLY.intValue())
    {
      return REFRESH_ONLY;
    }
    else if (intValue == REFRESH_AND_PERSIST.intValue())
    {
      return REFRESH_AND_PERSIST;
    }
    else
    {
      return null;
    }
  }
}
