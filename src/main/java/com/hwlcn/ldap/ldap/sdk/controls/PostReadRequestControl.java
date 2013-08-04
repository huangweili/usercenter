package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



/**
 * This class provides an implementation of the LDAP post-read request control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4527.txt">RFC 4527</A>.  It
 * may be used to request that the server retrieve a copy of the target entry as
 * it appeared immediately after processing an add, modify, or modify DN
 * operation.
 * <BR><BR>
 * If this control is included in an add, modify, or modify DN request, then the
 * corresponding response may include a {@link PostReadResponseControl}
 * containing a version of the entry as it appeared after applying that change.
 * Note that this response control will only be included if the operation was
 * successful, so it will not be provided if the operation failed for some
 * reason (e.g., if the change would have violated the server schema, or if the
 * requester did not have sufficient permission to perform that operation).
 * <BR><BR>
 * The value of this control should contain a set of requested attributes to
 * include in the entry that is returned.  The server should treat this set of
 * requested attributes exactly as it treats the requested attributes from a
 * {@link com.hwlcn.ldap.ldap.sdk.SearchRequest}.  As is the case with a search
 * request, if no attributes are specified, then all user attributes will be
 * included.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the post-read controls.  It
 * will modify an entry to increment the value of the {@code testCounter}
 * attribute by one, and will use the post-read controls to determine what the
 * new value is:
 * <PRE>
 *   Modification mod =
 *        new Modification(ModificationType.INCREMENT, "testCounter", "1");
 *   ModifyRequest modifyRequest =
 *        new ModifyRequest("uid=john.doe,ou=People,dc=example,dc=com", mod);
 *   modifyRequest.addControl(new PostReadRequestControl("testCounter"));
 *   LDAPResult modifyResult = connection.modify(modifyRequest);
 *
 *   Integer newValue = null;
 *   PostReadResponseControl c = PostReadResponseControl.get(modifyResult);
 *   if (c != null)
 *   {
 *     newValue = c.getEntry().getAttributeValueAsInteger("testCounter");
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PostReadRequestControl
       extends Control
{

  public static final String POST_READ_REQUEST_OID = "1.3.6.1.1.13.2";

  private static final String[] NO_ATTRIBUTES = StaticUtils.NO_STRINGS;

  private static final long serialVersionUID = -4210061989410209462L;

  private final String[] attributes;

  public PostReadRequestControl(final String... attributes)
  {
    this(true, attributes);
  }

  public PostReadRequestControl(final boolean isCritical,
                                final String... attributes)
  {
    super(POST_READ_REQUEST_OID, isCritical, encodeValue(attributes));

    if (attributes == null)
    {
      this.attributes = NO_ATTRIBUTES;
    }
    else
    {
      this.attributes = attributes;
    }
  }

  public PostReadRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_POST_READ_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      attributes = new String[attrElements.length];
      for (int i=0; i < attrElements.length; i++)
      {
        attributes[i] =
             ASN1OctetString.decodeAsOctetString(attrElements[i]).stringValue();
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_POST_READ_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }

  private static ASN1OctetString encodeValue(final String[] attributes)
  {
    if ((attributes == null) || (attributes.length == 0))
    {
      return new ASN1OctetString(new ASN1Sequence().encode());
    }

    final ASN1OctetString[] elements = new ASN1OctetString[attributes.length];
    for (int i=0; i < attributes.length; i++)
    {
      elements[i] = new ASN1OctetString(attributes[i]);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }


  public String[] getAttributes()
  {
    return attributes;
  }



  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_POST_READ_REQUEST.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PostReadRequestControl(attributes={");
    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append('\'');
      buffer.append(attributes[i]);
      buffer.append('\'');
    }
    buffer.append("}, isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
