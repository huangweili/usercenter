package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPRebindAuth
       implements Serializable
{

  private static final long serialVersionUID = -844389460595019929L;


  private final String dn;

  private final String password;


  public LDAPRebindAuth(final String dn, final String password)
  {
    this.dn       = dn;
    this.password = password;
  }


  public String getDN()
  {
    return dn;
  }


  public String getPassword()
  {
    return password;
  }
}
