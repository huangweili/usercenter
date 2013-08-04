package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordExpiringControl
       extends Control
       implements DecodeableControl
{

  public static final String PASSWORD_EXPIRING_OID = "2.16.840.1.113730.3.4.5";

  private static final long serialVersionUID = 1250220480854441338L;

  private final int secondsUntilExpiration;


  PasswordExpiringControl()
  {
    secondsUntilExpiration = -1;
  }

  public PasswordExpiringControl(final int secondsUntilExpiration)
  {
    super(PASSWORD_EXPIRING_OID, false,
          new ASN1OctetString(String.valueOf(secondsUntilExpiration)));

    this.secondsUntilExpiration = secondsUntilExpiration;
  }


  public PasswordExpiringControl(final String oid, final boolean isCritical,
                                 final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRING_NO_VALUE.get());
    }

    try
    {
      secondsUntilExpiration = Integer.parseInt(value.stringValue());
    }
    catch (NumberFormatException nfe)
    {
      debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRING_VALUE_NOT_INTEGER.get(), nfe);
    }
  }


  public PasswordExpiringControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordExpiringControl(oid, isCritical, value);
  }


  public static PasswordExpiringControl get(final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_EXPIRING_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordExpiringControl)
    {
      return (PasswordExpiringControl) c;
    }
    else
    {
      return new PasswordExpiringControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }


  public int getSecondsUntilExpiration()
  {
    return secondsUntilExpiration;
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_EXPIRING.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordExpiringControl(secondsUntilExpiration=");
    buffer.append(secondsUntilExpiration);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
