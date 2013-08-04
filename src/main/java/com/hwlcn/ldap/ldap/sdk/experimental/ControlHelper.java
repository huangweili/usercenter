package com.hwlcn.ldap.ldap.sdk.experimental;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ControlHelper
{

  private ControlHelper()
  {

  }


  @InternalUseOnly()
  public static void registerDefaultResponseControls()
  {
    Control.registerDecodeableControl(
         ActiveDirectoryDirSyncControl.DIRSYNC_OID,
         new ActiveDirectoryDirSyncControl());
  }


  @InternalUseOnly()
  public static void registerNonCommercialResponseControls()
  {
    Control.registerDecodeableControl(
         DraftBeheraLDAPPasswordPolicy10ResponseControl.
              PASSWORD_POLICY_RESPONSE_OID,
         new DraftBeheraLDAPPasswordPolicy10ResponseControl());
  }
}
