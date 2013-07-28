package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ControlHelper
{

  private ControlHelper()
  {

  }



  @InternalUseOnly()
  public static void registerDefaultResponseControls()
  {
    Control.registerDecodeableControl(
         AuthorizationIdentityResponseControl.
              AUTHORIZATION_IDENTITY_RESPONSE_OID,
         new AuthorizationIdentityResponseControl());

    Control.registerDecodeableControl(
         ContentSyncDoneControl.SYNC_DONE_OID,
         new ContentSyncDoneControl());

    Control.registerDecodeableControl(
         ContentSyncStateControl.SYNC_STATE_OID,
         new ContentSyncStateControl());

    Control.registerDecodeableControl(
         EntryChangeNotificationControl.ENTRY_CHANGE_NOTIFICATION_OID,
         new EntryChangeNotificationControl());

    Control.registerDecodeableControl(
         PostReadResponseControl.POST_READ_RESPONSE_OID,
         new PostReadResponseControl());

    Control.registerDecodeableControl(
         PreReadResponseControl.PRE_READ_RESPONSE_OID,
         new PreReadResponseControl());

    Control.registerDecodeableControl(
         ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID,
         new ServerSideSortResponseControl());

    Control.registerDecodeableControl(
         SimplePagedResultsControl.PAGED_RESULTS_OID,
         new SimplePagedResultsControl());

    Control.registerDecodeableControl(
         PasswordExpiredControl.PASSWORD_EXPIRED_OID,
         new PasswordExpiredControl());

    Control.registerDecodeableControl(
         PasswordExpiringControl.PASSWORD_EXPIRING_OID,
         new PasswordExpiringControl());

    Control.registerDecodeableControl(
         VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID,
         new VirtualListViewResponseControl());
  }
}
