package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.BindResult;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuthorizationIdentityResponseControl
       extends Control
       implements DecodeableControl
{

  public static final String AUTHORIZATION_IDENTITY_RESPONSE_OID =
       "2.16.840.1.113730.3.4.15";

  private static final long serialVersionUID = -6315724175438820336L;


  private final String authorizationID;


  AuthorizationIdentityResponseControl()
  {
    authorizationID = null;
  }



  public AuthorizationIdentityResponseControl(final String authorizationID)
  {
    super(AUTHORIZATION_IDENTITY_RESPONSE_OID, false,
          new ASN1OctetString(authorizationID));

    ensureNotNull(authorizationID);

    this.authorizationID = authorizationID;
  }



  public AuthorizationIdentityResponseControl(final String oid,
                                              final boolean isCritical,
                                              final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_AUTHZID_RESPONSE_NO_VALUE.get());
    }
    else
    {
      authorizationID = value.stringValue();
    }
  }


  public AuthorizationIdentityResponseControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new AuthorizationIdentityResponseControl(oid, isCritical, value);
  }


  public static AuthorizationIdentityResponseControl
                     get(final BindResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(AUTHORIZATION_IDENTITY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof AuthorizationIdentityResponseControl)
    {
      return (AuthorizationIdentityResponseControl) c;
    }
    else
    {
      return new AuthorizationIdentityResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  public String getAuthorizationID()
  {
    return authorizationID;
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_AUTHZID_RESPONSE.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AuthorizationIdentityResponseControl(authorizationID='");
    buffer.append(authorizationID);
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
