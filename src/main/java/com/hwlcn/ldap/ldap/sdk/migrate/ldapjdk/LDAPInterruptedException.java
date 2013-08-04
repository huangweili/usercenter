package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPInterruptedException
       extends LDAPException
{

  private static final long serialVersionUID = 7867903105944011998L;


  LDAPInterruptedException()
  {
    super(null, ResultCode.USER_CANCELED_INT_VALUE);
  }


  LDAPInterruptedException(
       final com.hwlcn.ldap.ldap.sdk.LDAPException ldapException)
  {
    super(ldapException);
  }
}
