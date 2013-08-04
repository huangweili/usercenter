
package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of the proxied authorization V2
 * request control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4370.txt">RFC 4370</A>.  It may be used
 * to request that the associated operation be performed as if it has been
 * requested by some other user.
 * <BR><BR>
 * The target authorization identity for this control is specified as an
 * "authzId" value as described in section 5.2.1.8 of
 * <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is, it
 * should be either "dn:" followed by the distinguished name of the target user,
 * or "u:" followed by the username.  If the "u:" form is used, then the
 * mechanism used to resolve the provided username to an entry may vary from
 * server to server.
 * <BR><BR>
 * This control may be used in conjunction with add, delete, compare, delete,
 * extended, modify, modify DN, and search requests.  In that case, the
 * associated operation will be processed under the authority of the specified
 * authorization identity rather than the identity associated with the client
 * connection (i.e., the user as whom that connection is bound).  Note that
 * because of the inherent security risks associated with the use of the proxied
 * authorization control, most directory servers which support its use enforce
 * strict restrictions on the users that are allowed to request this control.
 * If a user attempts to use the proxied authorization V2 request control and
 * does not have sufficient permission to do so, then the server will return a
 * failure response with the {@link ResultCode#AUTHORIZATION_DENIED} result
 * code.
 * <BR><BR>
 * There is no corresponding response control for this request control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the proxied authorization V2
 * control to delete an entry under the authority of the user with DN
 * "uid=john.doe,ou=People,dc=example,dc=com":
 * <PRE>
 *   DeleteRequest deleteRequest =
 *        new DeleteRequest("cn=no longer needed,dc=example,dc=com");
 *   deleteRequest.addControl(new ProxiedAuthorizationV2RequestControl(
 *        "dn:uid=john.doe,ou=People,dc=example,dc=com"));
 *
 *   try
 *   {
 *     LDAPResult deleteResult = connection.delete(deleteRequest);
 *     // If we got here, then the delete was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     if (le.getResultCode() == ResultCode.AUTHORIZATION_DENIED)
 *     {
 *       // The delete failed because the authenticated user does not have
 *       // permission to use the proxied authorization V2 control.
 *     }
 *     else
 *     {
 *       // The delete failed for some other reason.
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ProxiedAuthorizationV2RequestControl
       extends Control
{

  public static final String PROXIED_AUTHORIZATION_V2_REQUEST_OID =
       "2.16.840.1.113730.3.4.18";

  private static final long serialVersionUID = 1054244283964851067L;

  private final String authorizationID;

  public ProxiedAuthorizationV2RequestControl(final String authorizationID)
  {
    super(PROXIED_AUTHORIZATION_V2_REQUEST_OID, true,
          new ASN1OctetString(authorizationID));

    ensureNotNull(authorizationID);

    this.authorizationID = authorizationID;
  }

  public ProxiedAuthorizationV2RequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXY_V2_NO_VALUE.get());
    }

    authorizationID = value.stringValue();
  }

  public String getAuthorizationID()
  {
    return authorizationID;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PROXIED_AUTHZ_V2_REQUEST.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ProxiedAuthorizationV2RequestControl(authorizationID='");
    buffer.append(authorizationID);
    buffer.append("')");
  }
}
