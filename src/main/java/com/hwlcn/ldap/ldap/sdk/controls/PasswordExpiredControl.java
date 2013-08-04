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



/**
 * This class provides an implementation of the password expired control as
 * described in draft-vchu-ldap-pwd-policy.  It may be included in the response
 * for an unsuccessful bind operation to indicate that the reason for the
 * failure is that the target user's password has expired and must be reset
 * before the user will be allowed to authenticate.  Some servers may also
 * include this control in a successful bind response to indicate that the
 * authenticated user must change his or her password before being allowed to
 * perform any other operation.
 * <BR><BR>
 * No request control is required to trigger the server to send the password
 * expired response control.  If the server supports the use of this control and
 * the corresponding bind operation meets the criteria for this control to be
 * included in the response, then it will be returned to the client.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates a process that may be used to perform a
 * simple bind to authenticate against the server and handle any password
 * expired or password expiring control that may be included in the response:
 * <PRE>
 *   BindRequest bindRequest =
 *        new SimpleBindRequest("uid=john.doe,ou=People,dc=example,dc=com",
 *                              "password");
 *   try
 *   {
 *     BindResult bindResult = connection.bind(bindRequest);
 *     for (Control c : bindResult.getResponseControls())
 *     {
 *       if (c instanceof PasswordExpiringControl)
 *       {
 *         System.err.println("WARNING:  Your password will expire in " +
 *              ((PasswordExpiringControl) c).getSecondsUntilExpiration() +
 *              " seconds.");
 *       }
 *       else if (c instanceof PasswordExpiredControl)
 *       {
 *         System.err.println("WARNING:  You must change your password " +
 *              "before you will be allowed to perform any other operations.");
 *       }
 *     }
 *   }
 *   catch (LDAPException le)
 *   {
 *     for (Control c : le.getResponseControls())
 *     {
 *       if (c instanceof PasswordExpiredControl)
 *       {
 *         System.err.println("ERROR:  Your password is expired.");
 *       }
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordExpiredControl
       extends Control
       implements DecodeableControl
{

  public static final String PASSWORD_EXPIRED_OID = "2.16.840.1.113730.3.4.4";


  private static final long serialVersionUID = -2731704592689892224L;


  public PasswordExpiredControl()
  {
    super(PASSWORD_EXPIRED_OID, false, new ASN1OctetString("0"));
  }

  public PasswordExpiredControl(final String oid, final boolean isCritical,
                                final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRED_NO_VALUE.get());
    }

    try
    {
      Integer.parseInt(value.stringValue());
    }
    catch (NumberFormatException nfe)
    {
      debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRED_VALUE_NOT_INTEGER.get(), nfe);
    }
  }


  public PasswordExpiredControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordExpiredControl(oid, isCritical, value);
  }

  public static PasswordExpiredControl get(final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_EXPIRED_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordExpiredControl)
    {
      return (PasswordExpiredControl) c;
    }
    else
    {
      return new PasswordExpiredControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_EXPIRED.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordExpiredControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
