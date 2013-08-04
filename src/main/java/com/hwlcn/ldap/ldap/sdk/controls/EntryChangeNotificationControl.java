
package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Constants;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1Long;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResultEntry;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EntryChangeNotificationControl
       extends Control
       implements DecodeableControl
{

  public static final String ENTRY_CHANGE_NOTIFICATION_OID =
       "2.16.840.1.113730.3.4.7";



  private static final long serialVersionUID = -1305357948140939303L;

 private final long changeNumber;

  private final PersistentSearchChangeType changeType;
 private final String previousDN;


  EntryChangeNotificationControl()
  {
    changeNumber = -1;
    changeType   = null;
    previousDN   = null;
  }



  public EntryChangeNotificationControl(
              final PersistentSearchChangeType changeType,
              final String previousDN, final long changeNumber)
  {
    this(changeType, previousDN, changeNumber, false);
  }


  public EntryChangeNotificationControl(
              final PersistentSearchChangeType changeType,
              final String previousDN, final long changeNumber,
              final boolean isCritical)
  {
    super(ENTRY_CHANGE_NOTIFICATION_OID, isCritical,
          encodeValue(changeType, previousDN, changeNumber));

    this.changeType   = changeType;
    this.previousDN   = previousDN;
    this.changeNumber = changeNumber;
  }



  public EntryChangeNotificationControl(final String oid,
                                        final boolean isCritical,
                                        final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_NO_VALUE.get());
    }

    final ASN1Sequence ecnSequence;
    try
    {
      final ASN1Element element = ASN1Element.decode(value.getValue());
      ecnSequence = ASN1Sequence.decodeAsSequence(element);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] ecnElements = ecnSequence.elements();
    if ((ecnElements.length < 1) || (ecnElements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_INVALID_ELEMENT_COUNT.get(
                                   ecnElements.length));
    }

    final ASN1Enumerated ecnEnumerated;
    try
    {
      ecnEnumerated = ASN1Enumerated.decodeAsEnumerated(ecnElements[0]);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_FIRST_NOT_ENUMERATED.get(ae), ae);
    }

    changeType = PersistentSearchChangeType.valueOf(ecnEnumerated.intValue());
    if (changeType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_INVALID_CHANGE_TYPE.get(
                                   ecnEnumerated.intValue()));
    }


    String prevDN = null;
    long   chgNum = -1;
    for (int i=1; i < ecnElements.length; i++)
    {
      switch (ecnElements[i].getType())
      {
        case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
          prevDN = ASN1OctetString.decodeAsOctetString(
                        ecnElements[i]).stringValue();
          break;

        case ASN1Constants.UNIVERSAL_INTEGER_TYPE:
          try
          {
            chgNum = ASN1Long.decodeAsLong(ecnElements[i]).longValue();
          }
          catch (final ASN1Exception ae)
          {
            debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_ECN_CANNOT_DECODE_CHANGE_NUMBER.get(ae),
                                    ae);
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ECN_INVALID_ELEMENT_TYPE.get(
                                       toHex(ecnElements[i].getType())));
      }
    }

    previousDN   = prevDN;
    changeNumber = chgNum;
  }


  public EntryChangeNotificationControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new EntryChangeNotificationControl(oid, isCritical, value);
  }


  public static EntryChangeNotificationControl
                     get(final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(ENTRY_CHANGE_NOTIFICATION_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof EntryChangeNotificationControl)
    {
      return (EntryChangeNotificationControl) c;
    }
    else
    {
      return new EntryChangeNotificationControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }

  private static ASN1OctetString encodeValue(
               final PersistentSearchChangeType changeType,
               final String previousDN, final long changeNumber)
  {
    ensureNotNull(changeType);

    final ArrayList<ASN1Element> elementList = new ArrayList<ASN1Element>(3);
    elementList.add(new ASN1Enumerated(changeType.intValue()));

    if (previousDN != null)
    {
      elementList.add(new ASN1OctetString(previousDN));
    }

    if (changeNumber > 0)
    {
      elementList.add(new ASN1Long(changeNumber));
    }

    return new ASN1OctetString(new ASN1Sequence(elementList).encode());
  }

  public PersistentSearchChangeType getChangeType()
  {
    return changeType;
  }


  public String getPreviousDN()
  {
    return previousDN;
  }


  public long getChangeNumber()
  {
    return changeNumber;
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ENTRY_CHANGE_NOTIFICATION.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EntryChangeNotificationControl(changeType=");
    buffer.append(changeType.getName());

    if (previousDN != null)
    {
      buffer.append(", previousDN='");
      buffer.append(previousDN);
      buffer.append('\'');
    }

    if (changeNumber > 0)
    {
      buffer.append(", changeNumber=");
      buffer.append(changeNumber);
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
