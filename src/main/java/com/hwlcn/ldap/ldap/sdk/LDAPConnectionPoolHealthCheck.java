package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public class LDAPConnectionPoolHealthCheck
{

  public LDAPConnectionPoolHealthCheck()
  {
  }




  public void ensureNewConnectionValid(final LDAPConnection connection)
         throws LDAPException
  {

  }



  public void ensureConnectionValidForCheckout(final LDAPConnection connection)
         throws LDAPException
  {

  }




  public void ensureConnectionValidForRelease(final LDAPConnection connection)
         throws LDAPException
  {

  }



  public void ensureConnectionValidForContinuedUse(
                   final LDAPConnection connection)
         throws LDAPException
  {

  }



  public void ensureConnectionValidAfterException(
                   final LDAPConnection connection,
                   final LDAPException exception)
         throws LDAPException
  {
    if (! ResultCode.isConnectionUsable(exception.getResultCode()))
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_POOL_HEALTH_CHECK_CONN_INVALID_AFTER_EXCEPTION.get(
                getExceptionMessage(exception)),
           exception);
    }
  }



  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionPoolHealthCheck()");
  }
}
