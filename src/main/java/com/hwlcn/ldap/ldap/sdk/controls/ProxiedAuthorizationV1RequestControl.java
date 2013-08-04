package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of the proxied authorization V1
 * request control, which may be used to request that the associated operation
 * be performed as if it had been requested by some other user.  It is based on
 * the specification provided in early versions of the
 * draft-weltman-ldapv3-proxy Internet Draft (this implementation is based on
 * the "-04" revision).  Later versions of the draft, and subsequently
 * <A HREF="http://www.ietf.org/rfc/rfc4370.txt">RFC 4370</A>, define a second
 * version of the proxied authorization control with a different OID and
 * different value format.  This control is supported primarily for legacy
 * purposes, and it is recommended that new applications use the
 * {@link ProxiedAuthorizationV2RequestControl} instead if this version.
 * <BR><BR>
 * The value of this control includes the DN of the user as whom the operation
 * should be performed.  Note that it should be a distinguished name, and not an
 * authzId value as is used in the proxied authorization V2 control.
 * <BR><BR>
 * This control may be used in conjunction with add, delete, compare, delete,
 * extended, modify, modify DN, and search requests.  In that case, the
 * associated operation will be processed under the authority of the specified
 * authorization identity rather than the identity associated with the client
 * connection (i.e., the user as whom that connection is bound).  Note that
 * because of the inherent security risks associated with the use of the proxied
 * authorization control, most directory servers which support its use enforce
 * strict restrictions on the users that are allowed to request this control.
 * Note that while the directory server should return a
 * {@link ResultCode#AUTHORIZATION_DENIED} result for a proxied authorization V2
 * control if the requester does not have the appropriate permission to use that
 * control, this result will not necessarily be used for the same condition with
 * the proxied authorization V1 control because this result code was not defined
 * until the release of the proxied authorization V2 specification.
 * code.
 * <BR><BR>
 * There is no corresponding response control for this request control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the proxied authorization V1
 * control to delete an entry under the authority of the user with DN
 * "uid=john.doe,ou=People,dc=example,dc=com":
 * <PRE>
 *   DeleteRequest deleteRequest =
 *        new DeleteRequest("cn=no longer needed,dc=example,dc=com");
 *   deleteRequest.addControl(new ProxiedAuthorizationV1RequestControl(
 *        "uid=john.doe,ou=People,dc=example,dc=com"));
 *
 *   try
 *   {
 *     LDAPResult deleteResult = connection.delete(deleteRequest);
 *     // If we got here, then the delete was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     // The delete failed for some reason.  It may or may not have been
 *     // because the authenticated user does not have permission to use the
 *     // proxied authorization V1 control.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ProxiedAuthorizationV1RequestControl
       extends Control
{

  public static final String PROXIED_AUTHORIZATION_V1_REQUEST_OID =
       "2.16.840.1.113730.3.4.12";

  private static final long serialVersionUID = 7312632337431962774L;

  private final String proxyDN;

  public ProxiedAuthorizationV1RequestControl(final String proxyDN)
  {
    super(PROXIED_AUTHORIZATION_V1_REQUEST_OID, true, encodeValue(proxyDN));

    ensureNotNull(proxyDN);

    this.proxyDN = proxyDN;
  }


  public ProxiedAuthorizationV1RequestControl(final DN proxyDN)
  {
    super(PROXIED_AUTHORIZATION_V1_REQUEST_OID, true,
          encodeValue(proxyDN.toString()));

    this.proxyDN = proxyDN.toString();
  }


  public ProxiedAuthorizationV1RequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXY_V1_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      proxyDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXYV1_DECODE_ERROR.get(e), e);
    }
  }


  private static ASN1OctetString encodeValue(final String proxyDN)
  {
    final ASN1Element[] valueElements =
    {
      new ASN1OctetString(proxyDN)
    };

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }


  public String getProxyDN()
  {
    return proxyDN;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PROXIED_AUTHZ_V1_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ProxiedAuthorizationV1RequestControl(proxyDN='");
    buffer.append(proxyDN);
    buffer.append("')");
  }
}
