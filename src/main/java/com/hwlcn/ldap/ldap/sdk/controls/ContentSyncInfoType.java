package com.hwlcn.ldap.ldap.sdk.controls;




public enum ContentSyncInfoType
{

  NEW_COOKIE((byte) 0x80),



  REFRESH_DELETE((byte) 0xA1),



  REFRESH_PRESENT((byte) 0xA2),



  SYNC_ID_SET((byte) 0xA3);


  private final byte type;




  private ContentSyncInfoType(final byte type)
  {
    this.type = type;
  }


  public byte getType()
  {
    return type;
  }


  public static ContentSyncInfoType valueOf(final byte type)
  {
    if (type == NEW_COOKIE.getType())
    {
      return NEW_COOKIE;
    }
    else if (type == REFRESH_DELETE.getType())
    {
      return REFRESH_DELETE;
    }
    else if (type == REFRESH_PRESENT.getType())
    {
      return REFRESH_PRESENT;
    }
    else if (type == SYNC_ID_SET.getType())
    {
      return SYNC_ID_SET;
    }
    else
    {
      return null;
    }
  }
}
