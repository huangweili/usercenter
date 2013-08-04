package com.hwlcn.ldap.ldap.sdk.controls;


public enum ContentSyncState
{

  PRESENT(0),

  ADD(1),

  MODIFY(2),

  DELETE(3);

  private final int intValue;

  private ContentSyncState(final int intValue)
  {
    this.intValue = intValue;
  }

  public int intValue()
  {
    return intValue;
  }


  public static ContentSyncState valueOf(final int intValue)
  {
    if (intValue == PRESENT.intValue())
    {
      return PRESENT;
    }
    else if (intValue == ADD.intValue())
    {
      return ADD;
    }
    else if (intValue == MODIFY.intValue())
    {
      return MODIFY;
    }
    else if (intValue == DELETE.intValue())
    {
      return DELETE;
    }
    else
    {
      return null;
    }
  }
}
