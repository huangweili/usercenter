
package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Constants;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ContentSyncRequestControl
       extends Control
{

  public static final String SYNC_REQUEST_OID = "1.3.6.1.4.1.4203.1.9.1.1";

  private static final long serialVersionUID = -3183343423271667072L;

  private final ASN1OctetString cookie;

  private final boolean reloadHint;

  private final ContentSyncRequestMode mode;

  public ContentSyncRequestControl(final ContentSyncRequestMode mode)
  {
    this(true, mode, null, false);
  }



  public ContentSyncRequestControl(final ContentSyncRequestMode mode,
                                   final ASN1OctetString cookie,
                                   final boolean reloadHint)
  {
    this(true, mode, cookie, reloadHint);
  }

  public ContentSyncRequestControl(final boolean isCritical,
                                   final ContentSyncRequestMode mode,
                                   final ASN1OctetString cookie,
                                   final boolean reloadHint)
  {
    super(SYNC_REQUEST_OID, isCritical, encodeValue(mode, cookie, reloadHint));

    this.mode       = mode;
    this.cookie     = cookie;
    this.reloadHint = reloadHint;
  }

  public ContentSyncRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_REQUEST_NO_VALUE.get());
    }

    ASN1OctetString        c = null;
    Boolean                h = null;
    ContentSyncRequestMode m = null;

    try
    {
      final ASN1Sequence s = ASN1Sequence.decodeAsSequence(value.getValue());
      for (final ASN1Element e : s.elements())
      {
        switch (e.getType())
        {
          case ASN1Constants.UNIVERSAL_ENUMERATED_TYPE:
            if (m != null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_MODES.get());
            }

            final ASN1Enumerated modeElement =
                 ASN1Enumerated.decodeAsEnumerated(e);
            m = ContentSyncRequestMode.valueOf(modeElement.intValue());
            if (m == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_INVALID_MODE.get(
                        modeElement.intValue()));
            }
            break;

          case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
            if (c == null)
            {
              c = ASN1OctetString.decodeAsOctetString(e);
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_COOKIES.get());
            }
            break;

          case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
            if (h == null)
            {
              h = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_HINTS.get());
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SYNC_REQUEST_VALUE_INVALID_ELEMENT_TYPE.get(
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
           ERR_SYNC_REQUEST_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    if (m == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_REQUEST_VALUE_NO_MODE.get());
    }
    else
    {
      mode = m;
    }

    if (h == null)
    {
      reloadHint = false;
    }
    else
    {
      reloadHint = h;
    }

    cookie = c;
  }


  private static ASN1OctetString encodeValue(final ContentSyncRequestMode mode,
                                             final ASN1OctetString cookie,
                                             final boolean reloadHint)
  {
    Validator.ensureNotNull(mode);

    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);
    elements.add(new ASN1Enumerated(mode.intValue()));

    if (cookie != null)
    {
      elements.add(cookie);
    }

    if (reloadHint)
    {
      elements.add(ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }


  public ContentSyncRequestMode getMode()
  {
    return mode;
  }



  public ASN1OctetString getCookie()
  {
    return cookie;
  }


  public boolean getReloadHint()
  {
    return reloadHint;
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CONTENT_SYNC_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ContentSyncRequestControl(mode='");
    buffer.append(mode.name());
    buffer.append('\'');

    if (cookie != null)
    {
      buffer.append(", cookie='");
      StaticUtils.toHex(cookie.getValue(), buffer);
      buffer.append('\'');
    }

    buffer.append(", reloadHint=");
    buffer.append(reloadHint);
    buffer.append(')');
  }
}
