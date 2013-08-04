
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
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResultEntry;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultEntryProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = 6501366526364541767L;

  private final List<Attribute> attributes;

  private final String dn;

  public SearchResultEntryProtocolOp(final String dn,
                                     final List<Attribute> attributes)
  {
    this.dn         = dn;
    this.attributes = Collections.unmodifiableList(attributes);
  }

  public SearchResultEntryProtocolOp(final Entry entry)
  {
    dn = entry.getDN();
    attributes = Collections.unmodifiableList(new ArrayList<Attribute>(
         entry.getAttributes()));
  }

  SearchResultEntryProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();
      ensureNotNull(dn);

      final ArrayList<Attribute> attrs = new ArrayList<Attribute>(10);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrs.add(Attribute.readFrom(reader));
      }

      attributes = Collections.unmodifiableList(attrs);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_ENTRY_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public String getDN()
  {
    return dn;
  }

  public List<Attribute> getAttributes()
  {
    return attributes;
  }

  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY;
  }

  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<ASN1Element>(attributes.size());
    for (final Attribute a : attributes)
    {
      attrElements.add(a.encode());
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY,
         new ASN1OctetString(dn),
         new ASN1Sequence(attrElements));
  }

  public static SearchResultEntryProtocolOp decodeProtocolOp(
                                                 final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final ArrayList<Attribute> attributes =
           new ArrayList<Attribute>(attrElements.length);
      for (final ASN1Element e : attrElements)
      {
        attributes.add(Attribute.decode(ASN1Sequence.decodeAsSequence(e)));
      }

      return new SearchResultEntryProtocolOp(dn, attributes);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_ENTRY_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }

  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY);
    buffer.addOctetString(dn);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final Attribute a : attributes)
    {
      a.writeTo(buffer);
    }
    attrSequence.end();
    opSequence.end();
  }

  public SearchResultEntry toSearchResultEntry(final Control... controls)
  {
    return new SearchResultEntry(dn, attributes, controls);
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
    buffer.append("SearchResultEntryProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', attrs={");

    final Iterator<Attribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
