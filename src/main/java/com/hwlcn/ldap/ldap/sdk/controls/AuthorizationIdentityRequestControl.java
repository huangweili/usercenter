package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the authorization identity bind
 * request control as described in
 * <A HREF="http://www.ietf.org/rfc/rfc3829.txt">RFC 3829</A>.  It may be
 * included in a bind request to request that the server include the
 * authorization identity associated with the client connection in the bind
 * response message, in the form of an
 * {@link AuthorizationIdentityResponseControl}.
 * <BR><BR>
 * The authorization identity request control is similar to the "Who Am I?"
 * extended request as implemented in the
 * {@link com.hwlcn.ldap.ldap.sdk.extensions.WhoAmIExtendedRequest} class.  The
 * primary difference between them is that the "Who Am I?" extended request can
 * be used at any time but requires a separate operation, while the
 * authorization identity request control can be included only with a bind
 * request but does not require a separate operation.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the authorization identity
 * request and response controls.  It authenticates to the directory server and
 * attempts to retrieve the authorization identity from the response:
 * <PRE>
 *   String authzID = null;
 *   BindRequest bindRequest =
 *        new SimpleBindRequest("uid=john.doe,ou=People,dc=example,dc=com",
 *                              "password",
 *                              new AuthorizationIdentityRequestControl());
 *
 *   BindResult bindResult = connection.bind(bindRequest);
 *   AuthorizationIdentityResponseControl c =
 *        AuthorizationIdentityResponseControl.get(bindResult);
 *   if (c != null)
 *   {
 *     authzID = c.getAuthorizationID();
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuthorizationIdentityRequestControl
       extends Control
{

  public static final String AUTHORIZATION_IDENTITY_REQUEST_OID =
       "2.16.840.1.113730.3.4.16";


  private static final long serialVersionUID = -4059607155175828138L;

  public AuthorizationIdentityRequestControl()
  {
    super(AUTHORIZATION_IDENTITY_REQUEST_OID, false, null);
  }



  public AuthorizationIdentityRequestControl(final boolean isCritical)
  {
    super(AUTHORIZATION_IDENTITY_REQUEST_OID, isCritical, null);
  }



  public AuthorizationIdentityRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_AUTHZID_REQUEST_HAS_VALUE.get());
    }
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_AUTHZID_REQUEST.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AuthorizationIdentityRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
