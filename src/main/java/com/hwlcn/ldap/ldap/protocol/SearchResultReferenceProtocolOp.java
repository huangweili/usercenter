
package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResultReference;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReferenceProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = -1526778443581862609L;


  private final List<String> referralURLs;


  public SearchResultReferenceProtocolOp(final List<String> referralURLs)
  {
    this.referralURLs = Collections.unmodifiableList(referralURLs);
  }


  public SearchResultReferenceProtocolOp(final SearchResultReference reference)
  {
    referralURLs = toList(reference.getReferralURLs());
  }

  SearchResultReferenceProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ArrayList<String> refs = new ArrayList<String>(5);
      final ASN1StreamReaderSequence refSequence = reader.beginSequence();
      while (refSequence.hasMoreElements())
      {
        refs.add(reader.readString());
      }

      referralURLs = Collections.unmodifiableList(refs);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public List<String> getReferralURLs()
  {
    return referralURLs;
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE;
  }

  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> urlElements =
         new ArrayList<ASN1Element>(referralURLs.size());
    for (final String url : referralURLs)
    {
      urlElements.add(new ASN1OctetString(url));
    }

    return new ASN1Sequence(
         LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE,
         urlElements);
  }

  public static SearchResultReferenceProtocolOp decodeProtocolOp(
                                                     final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] urlElements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final ArrayList<String> referralURLs =
           new ArrayList<String>(urlElements.length);
      for (final ASN1Element e : urlElements)
      {
        referralURLs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }

      return new SearchResultReferenceProtocolOp(referralURLs);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }

  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence = buffer.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE);
    for (final String s : referralURLs)
    {
      buffer.addOctetString(s);
    }
    opSequence.end();
  }

  public SearchResultReference toSearchResultReference(
                                    final Control... controls)
  {
    final String[] referralArray = new String[referralURLs.size()];
    referralURLs.toArray(referralArray);

    return new SearchResultReference(referralArray, controls);
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
    buffer.append("SearchResultReferenceProtocolOp(referralURLs={");

    final Iterator<String> iterator = referralURLs.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next());
      buffer.append('\'');
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
