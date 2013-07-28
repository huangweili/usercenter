package com.hwlcn.ldap.ldap.sdk.controls;



import java.io.Serializable;
import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SortKey
       implements Serializable
{

  private static final byte TYPE_MATCHING_RULE_ID = (byte) 0x80;


  private static final byte TYPE_REVERSE_ORDER = (byte) 0x81;


  private static final long serialVersionUID = -8631224188301402858L;



  private final boolean reverseOrder;


  private final String attributeName;


  private final String matchingRuleID;



  public SortKey(final String attributeName)
  {
    this(attributeName, null, false);
  }



  public SortKey(final String attributeName, final boolean reverseOrder)
  {
    this(attributeName, null, reverseOrder);
  }



  public SortKey(final String attributeName, final String matchingRuleID,
                 final boolean reverseOrder)
  {
    ensureNotNull(attributeName);

    this.attributeName  = attributeName;
    this.matchingRuleID = matchingRuleID;
    this.reverseOrder   = reverseOrder;
  }



  public String getAttributeName()
  {
    return attributeName;
  }




  public String getMatchingRuleID()
  {
    return matchingRuleID;
  }



  public boolean reverseOrder()
  {
    return reverseOrder;
  }



  ASN1Sequence encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);
    elements.add(new ASN1OctetString(attributeName));

    if (matchingRuleID != null)
    {
      elements.add(new ASN1OctetString(TYPE_MATCHING_RULE_ID, matchingRuleID));
    }

    if (reverseOrder)
    {
      elements.add(new ASN1Boolean(TYPE_REVERSE_ORDER, reverseOrder));
    }

    return new ASN1Sequence(elements);
  }




  public static SortKey decode(final ASN1Element element)
         throws LDAPException
  {
    final ASN1Element[] elements;
    try
    {
      elements = ASN1Sequence.decodeAsSequence(element).elements();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_KEY_NOT_SEQUENCE.get(e), e);
    }

    if ((elements.length < 1) || (elements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_KEY_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    boolean reverseOrder   = false;
    String  matchingRuleID = null;
    final String  attributeName  =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    for (int i=1; i < elements.length; i++)
    {
      switch (elements[i].getType())
      {
        case TYPE_MATCHING_RULE_ID:
          matchingRuleID =
               ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
          break;

        case TYPE_REVERSE_ORDER:
          try
          {
            reverseOrder =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
          }
          catch (Exception e)
          {
            debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_SORT_KEY_REVERSE_NOT_BOOLEAN.get(e), e);
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_SORT_KEY_ELEMENT_INVALID_TYPE.get(
                                       toHex(elements[i].getType())));
      }
    }

    return new SortKey(attributeName, matchingRuleID, reverseOrder);
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("SortKey(attributeName=");
    buffer.append(attributeName);

    if (matchingRuleID != null)
    {
      buffer.append(", matchingRuleID=");
      buffer.append(matchingRuleID);
    }

    buffer.append(", reverseOrder=");
    buffer.append(reverseOrder);
    buffer.append(')');
  }
}
