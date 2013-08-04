package com.hwlcn.ldap.ldap.sdk.extensions;


import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import com.hwlcn.ldap.asn1.ASN1Constants;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EndTransactionExtendedResult
       extends ExtendedResult
{

  private static final long serialVersionUID = 1514265185948328221L;

  private final int failedOpMessageID;

  private final TreeMap<Integer,Control[]> opResponseControls;

  public EndTransactionExtendedResult(final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    opResponseControls = new TreeMap<Integer,Control[]>();

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      failedOpMessageID = -1;
      return;
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_RESPONSE_VALUE_NOT_SEQUENCE.get(ae.getMessage()), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length == 0)
    {
      failedOpMessageID = -1;
      return;
    }
    else if (valueElements.length > 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_RESPONSE_INVALID_ELEMENT_COUNT.get(
                valueElements.length));
    }

    int msgID = -1;
    for (final ASN1Element e : valueElements)
    {
      if (e.getType() == ASN1Constants.UNIVERSAL_INTEGER_TYPE)
      {
        try
        {
          msgID = ASN1Integer.decodeAsInteger(e).intValue();
        }
        catch (final ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_END_TXN_RESPONSE_CANNOT_DECODE_MSGID.get(ae), ae);
        }
      }
      else if (e.getType() == ASN1Constants.UNIVERSAL_SEQUENCE_TYPE)
      {
        decodeOpControls(e, opResponseControls);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_INVALID_TYPE.get(toHex(e.getType())));
      }
    }

    failedOpMessageID = msgID;
  }

  public EndTransactionExtendedResult(final int messageID,
              final ResultCode resultCode, final String diagnosticMessage,
              final String matchedDN, final String[] referralURLs,
              final Integer failedOpMessageID,
              final Map<Integer,Control[]> opResponseControls,
              final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(failedOpMessageID, opResponseControls),
                            responseControls);

    if ((failedOpMessageID == null) || (failedOpMessageID <= 0))
    {
      this.failedOpMessageID = -1;
    }
    else
    {
      this.failedOpMessageID = failedOpMessageID;
    }

    if (opResponseControls == null)
    {
      this.opResponseControls = new TreeMap<Integer,Control[]>();
    }
    else
    {
      this.opResponseControls =
           new TreeMap<Integer,Control[]>(opResponseControls);
    }
  }

  private static void decodeOpControls(final ASN1Element element,
                                       final Map<Integer,Control[]> controlMap)
          throws LDAPException
  {
    final ASN1Sequence ctlsSequence;
    try
    {
      ctlsSequence = ASN1Sequence.decodeAsSequence(element);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_END_TXN_RESPONSE_CONTROLS_NOT_SEQUENCE.get(ae), ae);
    }

    for (final ASN1Element e : ctlsSequence.elements())
    {
      final ASN1Sequence ctlSequence;
      try
      {
        ctlSequence = ASN1Sequence.decodeAsSequence(e);
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_END_TXN_RESPONSE_CONTROL_NOT_SEQUENCE.get(ae), ae);
      }

      final ASN1Element[] ctlSequenceElements = ctlSequence.elements();
      if (ctlSequenceElements.length != 2)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_END_TXN_RESPONSE_CONTROL_INVALID_ELEMENT_COUNT.get(
                            ctlSequenceElements.length));
      }

      final int msgID;
      try
      {
        msgID = ASN1Integer.decodeAsInteger(ctlSequenceElements[0]).intValue();
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_END_TXN_RESPONSE_CONTROL_MSGID_NOT_INT.get(ae), ae);
      }

      final ASN1Sequence controlsSequence;
      try
      {
        controlsSequence =
             ASN1Sequence.decodeAsSequence(ctlSequenceElements[1]);
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_CONTROLS_ELEMENT_NOT_SEQUENCE.get(ae), ae);
      }

      final Control[] controls = Control.decodeControls(controlsSequence);
      if (controls.length == 0)
      {
        continue;
      }

      controlMap.put(msgID, controls);
    }
  }

  private static ASN1OctetString encodeValue(final Integer failedOpMessageID,
                      final Map<Integer,Control[]> opResponseControls)
  {
    if ((failedOpMessageID == null) && (opResponseControls == null))
    {
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(2);
    if (failedOpMessageID != null)
    {
      elements.add(new ASN1Integer(failedOpMessageID));
    }

    if ((opResponseControls != null) && (! opResponseControls.isEmpty()))
    {
      final ArrayList<ASN1Element> controlElements =
           new ArrayList<ASN1Element>();
      for (final Map.Entry<Integer,Control[]> e : opResponseControls.entrySet())
      {
        final ASN1Element[] ctlElements =
        {
          new ASN1Integer(e.getKey()),
          Control.encodeControls(e.getValue())
        };
        controlElements.add(new ASN1Sequence(ctlElements));
      }

      elements.add(new ASN1Sequence(controlElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }

  public int getFailedOpMessageID()
  {
    return failedOpMessageID;
  }

  public Map<Integer,Control[]> getOperationResponseControls()
  {
    return opResponseControls;
  }

  public Control[] getOperationResponseControls(final int messageID)
  {
    return opResponseControls.get(messageID);
  }

  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_END_TXN.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EndTransactionExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (failedOpMessageID > 0)
    {
      buffer.append(", failedOpMessageID=");
      buffer.append(failedOpMessageID);
    }

    if (! opResponseControls.isEmpty())
    {
      buffer.append(", opResponseControls={");

      for (final int msgID : opResponseControls.keySet())
      {
        buffer.append("opMsgID=");
        buffer.append(msgID);
        buffer.append(", opControls={");

        boolean first = true;
        for (final Control c : opResponseControls.get(msgID))
        {
          if (first)
          {
            first = false;
          }
          else
          {
            buffer.append(", ");
          }

          buffer.append(c);
        }
        buffer.append('}');
      }

      buffer.append('}');
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
