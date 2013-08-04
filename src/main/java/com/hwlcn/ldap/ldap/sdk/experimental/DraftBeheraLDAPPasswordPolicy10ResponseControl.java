
package com.hwlcn.ldap.ldap.sdk.experimental;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.experimental.ExperimentalMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftBeheraLDAPPasswordPolicy10ResponseControl
       extends Control
       implements DecodeableControl
{

  public static final String PASSWORD_POLICY_RESPONSE_OID =
       "1.3.6.1.4.1.42.2.27.8.5.1";

  private static final byte TYPE_WARNING = (byte) 0xA0;

  private static final byte TYPE_ERROR = (byte) 0x81;

  private static final byte TYPE_TIME_BEFORE_EXPIRATION = (byte) 0x80;

  private static final byte TYPE_GRACE_LOGINS_REMAINING = (byte) 0x81;

  private static final long serialVersionUID = 1835830253434331833L;

  private final int warningValue;

  private final DraftBeheraLDAPPasswordPolicy10ErrorType errorType;

  private final DraftBeheraLDAPPasswordPolicy10WarningType warningType;

  DraftBeheraLDAPPasswordPolicy10ResponseControl()
  {
    warningType  = null;
    errorType    = null;
    warningValue = -1;
  }

  public DraftBeheraLDAPPasswordPolicy10ResponseControl(
              final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
              final int warningValue,
              final DraftBeheraLDAPPasswordPolicy10ErrorType errorType)
  {
    this(warningType, warningValue, errorType, false);
  }

  public DraftBeheraLDAPPasswordPolicy10ResponseControl(
              final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
              final int warningValue,
              final DraftBeheraLDAPPasswordPolicy10ErrorType errorType,
              final boolean isCritical)
  {
    super(PASSWORD_POLICY_RESPONSE_OID, isCritical,
          encodeValue(warningType, warningValue, errorType));

    this.warningType = warningType;
    this.errorType   = errorType;

    if (warningType == null)
    {
      this.warningValue = -1;
    }
    else
    {
      this.warningValue = warningValue;
    }
  }

  public DraftBeheraLDAPPasswordPolicy10ResponseControl(final String oid,
              final boolean isCritical, final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length > 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    int                                        wv = -1;
    DraftBeheraLDAPPasswordPolicy10ErrorType   et = null;
    DraftBeheraLDAPPasswordPolicy10WarningType wt = null;
    for (final ASN1Element e : valueElements)
    {
      switch (e.getType())
      {
        case TYPE_WARNING:
          if (wt == null)
          {
            try
            {
              final ASN1Element warningElement =
                   ASN1Element.decode(e.getValue());
              wv = ASN1Integer.decodeAsInteger(warningElement).intValue();
              switch (warningElement.getType())
              {
                case TYPE_TIME_BEFORE_EXPIRATION:
                  wt = DraftBeheraLDAPPasswordPolicy10WarningType.
                       TIME_BEFORE_EXPIRATION;
                  break;

                case TYPE_GRACE_LOGINS_REMAINING:
                  wt = DraftBeheraLDAPPasswordPolicy10WarningType.
                       GRACE_LOGINS_REMAINING;
                  break;

                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_PWP_RESPONSE_INVALID_WARNING_TYPE.get(
                                      toHex(warningElement.getType())));
              }
            }
            catch (ASN1Exception ae)
            {
              debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                             ERR_PWP_RESPONSE_CANNOT_DECODE_WARNING.get(ae),
                             ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_PWP_RESPONSE_MULTIPLE_WARNING.get());
          }
          break;

        case TYPE_ERROR:
          if (et == null)
          {
            try
            {
              final ASN1Enumerated errorElement =
                   ASN1Enumerated.decodeAsEnumerated(e);
              et = DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(
                   errorElement.intValue());
              if (et == null)
              {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_PWP_RESPONSE_INVALID_ERROR_TYPE.get(
                                      errorElement.intValue()));
              }
            }
            catch (ASN1Exception ae)
            {
              debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                             ERR_PWP_RESPONSE_CANNOT_DECODE_ERROR.get(ae), ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_PWP_RESPONSE_MULTIPLE_ERROR.get());
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_PWP_RESPONSE_INVALID_TYPE.get(
                                       toHex(e.getType())));
      }
    }

    warningType  = wt;
    warningValue = wv;
    errorType    = et;
  }


  public DraftBeheraLDAPPasswordPolicy10ResponseControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new DraftBeheraLDAPPasswordPolicy10ResponseControl(oid, isCritical,
         value);
  }

  public static DraftBeheraLDAPPasswordPolicy10ResponseControl get(
                     final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_POLICY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof DraftBeheraLDAPPasswordPolicy10ResponseControl)
    {
      return (DraftBeheraLDAPPasswordPolicy10ResponseControl) c;
    }
    else
    {
      return new DraftBeheraLDAPPasswordPolicy10ResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }


  private static ASN1OctetString encodeValue(
       final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
       final int warningValue,
       final DraftBeheraLDAPPasswordPolicy10ErrorType errorType)
  {
    final ArrayList<ASN1Element> valueElements = new ArrayList<ASN1Element>(2);

    if (warningType != null)
    {
      switch (warningType)
      {
        case TIME_BEFORE_EXPIRATION:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_TIME_BEFORE_EXPIRATION,
                               warningValue).encode()));
          break;

        case GRACE_LOGINS_REMAINING:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_GRACE_LOGINS_REMAINING,
                               warningValue).encode()));
          break;
      }
    }

    if (errorType != null)
    {
      valueElements.add(new ASN1Enumerated(TYPE_ERROR, errorType.intValue()));
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }

  public DraftBeheraLDAPPasswordPolicy10WarningType getWarningType()
  {
    return warningType;
  }

  public int getWarningValue()
  {
    return warningValue;
  }

  public DraftBeheraLDAPPasswordPolicy10ErrorType getErrorType()
  {
    return errorType;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_POLICY_RESPONSE.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    boolean elementAdded = false;

    buffer.append("PasswordPolicyResponseControl(");

    if (warningType != null)
    {
      buffer.append("warningType='");
      buffer.append(warningType.getName());
      buffer.append("', warningValue=");
      buffer.append(warningValue);
      elementAdded = true;
    }

    if (errorType != null)
    {
      if (elementAdded)
      {
        buffer.append(", ");
      }

      buffer.append("errorType='");
      buffer.append(errorType.getName());
      buffer.append('\'');
      elementAdded = true;
    }

    if (elementAdded)
    {
      buffer.append(", ");
    }

    buffer.append("isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
