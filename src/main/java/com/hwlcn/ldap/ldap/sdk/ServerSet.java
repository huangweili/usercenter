package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ServerSet
{

  protected ServerSet()
  {

  }


  public abstract LDAPConnection getConnection()
         throws LDAPException;

  public LDAPConnection getConnection(
                             final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    final LDAPConnection c = getConnection();

    if (healthCheck != null)
    {
      try
      {
        healthCheck.ensureNewConnectionValid(c);
      }
      catch (LDAPException le)
      {
        debugException(le);
        c.close();
        throw le;
      }
    }

    return c;
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public void toString(final StringBuilder buffer)
  {
    buffer.append("ServerSet(className=");
    buffer.append(getClass().getName());
    buffer.append(')');
  }
}
