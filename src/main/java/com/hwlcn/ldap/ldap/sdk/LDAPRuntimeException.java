package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.HwlcnException;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPRuntimeException
       extends HwlcnException
{

  private static final long serialVersionUID = 6201514484547092642L;

  private final LDAPException ldapException;


  public LDAPRuntimeException(final LDAPException ldapException)
  {
    super(ldapException.getMessage(), ldapException.getCause());

    this.ldapException = ldapException;
  }

  public LDAPException getLDAPException()
  {
    return ldapException;
  }

  public void throwLDAPException()
         throws LDAPException
  {
    throw ldapException;
  }


  public ResultCode getResultCode()
  {
    return ldapException.getResultCode();
  }

  public String getMatchedDN()
  {
    return ldapException.getMatchedDN();
  }

  public String getDiagnosticMessage()
  {
    return ldapException.getDiagnosticMessage();
  }


  public String[] getReferralURLs()
  {
    return ldapException.getReferralURLs();
  }

  public boolean hasResponseControl()
  {
    return ldapException.hasResponseControl();
  }


  public boolean hasResponseControl(final String oid)
  {
    return ldapException.hasResponseControl(oid);
  }

  public Control[] getResponseControls()
  {
    return ldapException.getResponseControls();
  }

  public Control getResponseControl(final String oid)
  {
    return ldapException.getResponseControl(oid);
  }

  public LDAPResult toLDAPResult()
  {
    return ldapException.toLDAPResult();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    ldapException.toString(buffer);
  }

  @Override()
  public String getExceptionMessage()
  {
    return ldapException.getExceptionMessage();
  }
}
