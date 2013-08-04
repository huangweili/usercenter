package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Constants;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ContentSyncDoneControl
       extends Control
       implements DecodeableControl
{

  public static final String SYNC_DONE_OID = "1.3.6.1.4.1.4203.1.9.1.3";



  private static final long serialVersionUID = -2723009401737612274L;



  private final ASN1OctetString cookie;

  private final boolean refreshDeletes;



  ContentSyncDoneControl()
  {
    cookie         = null;
    refreshDeletes = false;
  }



  public ContentSyncDoneControl(final ASN1OctetString cookie,
                                final boolean refreshDeletes)
  {
    super(SYNC_DONE_OID, false, encodeValue(cookie, refreshDeletes));

    this.cookie          = cookie;
    this.refreshDeletes = refreshDeletes;
  }



  public ContentSyncDoneControl(final String oid, final boolean isCritical,
                                final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_DONE_NO_VALUE.get());
    }

    ASN1OctetString c = null;
    Boolean         r = null;

    try
    {
      final ASN1Sequence s = ASN1Sequence.decodeAsSequence(value.getValue());
      for (final ASN1Element e : s.elements())
      {
        switch (e.getType())
        {
          case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
            if (c == null)
            {
              c = ASN1OctetString.decodeAsOctetString(e);
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_DONE_VALUE_MULTIPLE_COOKIES.get());
            }
            break;

          case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
            if (r == null)
            {
              r = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_DONE_VALUE_MULTIPLE_REFRESH_DELETE.get());
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SYNC_DONE_VALUE_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }
    }
    catch (final LDAPException le)
    {
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_DONE_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    cookie = c;

    if (r == null)
    {
      refreshDeletes = false;
    }
    else
    {
      refreshDeletes = r;
    }
  }


  private static ASN1OctetString encodeValue(final ASN1OctetString cookie,
                                             final boolean refreshDeletes)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(2);

    if (cookie != null)
    {
      elements.add(cookie);
    }

    if (refreshDeletes)
    {
      elements.add(new ASN1Boolean(refreshDeletes));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }


  public ContentSyncDoneControl decodeControl(final String oid,
                                              final boolean isCritical,
                                              final ASN1OctetString value)
         throws LDAPException
  {
    return new ContentSyncDoneControl(oid, isCritical, value);
  }




  public static ContentSyncDoneControl get(final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(SYNC_DONE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ContentSyncDoneControl)
    {
      return (ContentSyncDoneControl) c;
    }
    else
    {
      return new ContentSyncDoneControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }




  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  public boolean refreshDeletes()
  {
    return refreshDeletes;
  }



  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CONTENT_SYNC_DONE.get();
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ContentSyncDoneControl(");

    if (cookie != null)
    {
      buffer.append("cookie='");
      StaticUtils.toHex(cookie.getValue(), buffer);
      buffer.append("', ");
    }

    buffer.append("refreshDeletes=");
    buffer.append(refreshDeletes);
    buffer.append(')');
  }
}
