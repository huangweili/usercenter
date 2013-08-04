
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPResponse
       implements Serializable
{

  private static final long serialVersionUID = -8401666939604882177L;


  private final LDAPResult ldapResult;



  public LDAPResponse(final LDAPResult ldapResult)
  {
    this.ldapResult = ldapResult;
  }


  public int getMessageID()
  {
    return ldapResult.getMessageID();
  }

  public int getResultCode()
  {
    return ldapResult.getResultCode().intValue();
  }



  public String getErrorMessage()
  {
    return ldapResult.getDiagnosticMessage();
  }


  public String getMatchedDN()
  {
    return ldapResult.getMatchedDN();
  }


  public String[] getReferrals()
  {
    final String[] referrals = ldapResult.getReferralURLs();
    if (referrals.length == 0)
    {
      return null;
    }
    else
    {
      return referrals;
    }
  }

  public LDAPControl[] getControls()
  {
    final Control[] controls = ldapResult.getResponseControls();
    if (controls.length == 0)
    {
      return null;
    }

    return LDAPControl.toLDAPControls(controls);
  }


  public final LDAPResult toLDAPResult()
  {
    return ldapResult;
  }


  @Override()
  public String toString()
  {
    return ldapResult.toString();
  }
}
