package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;

@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareResponseProtocolOp
       extends GenericResponseProtocolOp
{

  private static final long serialVersionUID = 3237778285010810669L;




  public CompareResponseProtocolOp(final int resultCode, final String matchedDN,
                                 final String diagnosticMessage,
                                 final List<String> referralURLs)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE, resultCode, matchedDN,
          diagnosticMessage, referralURLs);
  }



  public CompareResponseProtocolOp(final LDAPResult result)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE,
         result.getResultCode().intValue(), result.getMatchedDN(),
         result.getDiagnosticMessage(),
         StaticUtils.toList(result.getReferralURLs()));
  }




  CompareResponseProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    super(reader);
  }



  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(4);
    elements.add(new ASN1Enumerated(getResultCode()));

    final String matchedDN = getMatchedDN();
    if (matchedDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(matchedDN));
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(diagnosticMessage));
    }

    final List<String> referralURLs = getReferralURLs();
    if (! referralURLs.isEmpty())
    {
      final ArrayList<ASN1Element> refElements =
           new ArrayList<ASN1Element>(referralURLs.size());
      for (final String r : referralURLs)
      {
        refElements.add(new ASN1OctetString(r));
      }
      elements.add(new ASN1Sequence(TYPE_REFERRALS, refElements));
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE,
         elements);
  }



  public static CompareResponseProtocolOp decodeProtocolOp(
                                               final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final int resultCode =
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue();

      final String matchedDN;
      final String md =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      if (md.length() > 0)
      {
        matchedDN = md;
      }
      else
      {
        matchedDN = null;
      }

      final String diagnosticMessage;
      final String dm =
           ASN1OctetString.decodeAsOctetString(elements[2]).stringValue();
      if (dm.length() > 0)
      {
        diagnosticMessage = dm;
      }
      else
      {
        diagnosticMessage = null;
      }

      final List<String> referralURLs;
      if (elements.length == 4)
      {
        final ASN1Element[] refElements =
             ASN1Sequence.decodeAsSequence(elements[3]).elements();
        referralURLs = new ArrayList<String>(refElements.length);
        for (final ASN1Element e : refElements)
        {
          referralURLs.add(
               ASN1OctetString.decodeAsOctetString(e).stringValue());
        }
      }
      else
      {
        referralURLs = null;
      }

      return new CompareResponseProtocolOp(resultCode, matchedDN,
           diagnosticMessage, referralURLs);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_COMPARE_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
