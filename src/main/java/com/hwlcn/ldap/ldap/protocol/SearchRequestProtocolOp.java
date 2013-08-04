
package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DereferencePolicy;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchRequest;
import com.hwlcn.ldap.ldap.sdk.SearchScope;
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
public final class SearchRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = -8521750809606744181L;

  private final boolean typesOnly;

  private final DereferencePolicy derefPolicy;

  private final Filter filter;

  private final int sizeLimit;

  private final int timeLimit;

  private final List<String> attributes;

  private final SearchScope scope;

  private final String baseDN;




  public SearchRequestProtocolOp(final String baseDN, final SearchScope scope,
              final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly, final Filter filter,
              final List<String> attributes)
  {
    this.scope       = scope;
    this.derefPolicy = derefPolicy;
    this.typesOnly   = typesOnly;
    this.filter      = filter;

    if (baseDN == null)
    {
      this.baseDN = "";
    }
    else
    {
      this.baseDN = baseDN;
    }

    if (sizeLimit > 0)
    {
      this.sizeLimit = sizeLimit;
    }
    else
    {
      this.sizeLimit = 0;
    }

    if (timeLimit > 0)
    {
      this.timeLimit = timeLimit;
    }
    else
    {
      this.timeLimit = 0;
    }

    if (attributes == null)
    {
      this.attributes = Collections.emptyList();
    }
    else
    {
      this.attributes = Collections.unmodifiableList(attributes);
    }
  }


  public SearchRequestProtocolOp(final SearchRequest request)
  {
    baseDN      = request.getBaseDN();
    scope       = request.getScope();
    derefPolicy = request.getDereferencePolicy();
    sizeLimit   = request.getSizeLimit();
    timeLimit   = request.getTimeLimitSeconds();
    typesOnly   = request.typesOnly();
    filter      = request.getFilter();
    attributes  = request.getAttributeList();
  }



  SearchRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      baseDN      = reader.readString();
      scope       = SearchScope.valueOf(reader.readEnumerated());
      derefPolicy = DereferencePolicy.valueOf(reader.readEnumerated());
      sizeLimit   = reader.readInteger();
      timeLimit   = reader.readInteger();
      typesOnly   = reader.readBoolean();
      filter      = Filter.readFrom(reader);

      final ArrayList<String> attrs = new ArrayList<String>(5);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrs.add(reader.readString());
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
           ERR_SEARCH_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }

  public String getBaseDN()
  {
    return baseDN;
  }


  public SearchScope getScope()
  {
    return scope;
  }


  public DereferencePolicy getDerefPolicy()
  {
    return derefPolicy;
  }



  public int getSizeLimit()
  {
    return sizeLimit;
  }

  public int getTimeLimit()
  {
    return timeLimit;
  }


  public boolean typesOnly()
  {
    return typesOnly;
  }


  public Filter getFilter()
  {
    return filter;
  }


  public List<String> getAttributes()
  {
    return attributes;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST;
  }


  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<ASN1Element>(attributes.size());
    for (final String attribute : attributes)
    {
      attrElements.add(new ASN1OctetString(attribute));
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
         new ASN1OctetString(baseDN),
         new ASN1Enumerated(scope.intValue()),
         new ASN1Enumerated(derefPolicy.intValue()),
         new ASN1Integer(sizeLimit),
         new ASN1Integer(timeLimit),
         new ASN1Boolean(typesOnly),
         filter.encode(),
         new ASN1Sequence(attrElements));
  }


  public static SearchRequestProtocolOp decodeProtocolOp(
                                             final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String baseDN =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      final SearchScope scope = SearchScope.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[1]).intValue());
      final DereferencePolicy derefPolicy = DereferencePolicy.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[2]).intValue());
      final int sizeLimit = ASN1Integer.decodeAsInteger(elements[3]).intValue();
      final int timeLimit = ASN1Integer.decodeAsInteger(elements[4]).intValue();
      final boolean typesOnly =
           ASN1Boolean.decodeAsBoolean(elements[5]).booleanValue();
      final Filter filter = Filter.decode(elements[6]);

      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(elements[7]).elements();
      final ArrayList<String> attributes =
           new ArrayList<String>(attrElements.length);
      for (final ASN1Element e : attrElements)
      {
        attributes.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }

      return new SearchRequestProtocolOp(baseDN, scope, derefPolicy, sizeLimit,
           timeLimit, typesOnly, filter, attributes);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST);
    buffer.addOctetString(baseDN);
    buffer.addEnumerated(scope.intValue());
    buffer.addEnumerated(derefPolicy.intValue());
    buffer.addInteger(sizeLimit);
    buffer.addInteger(timeLimit);
    buffer.addBoolean(typesOnly);
    filter.writeTo(buffer);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final String s : attributes)
    {
      buffer.addOctetString(s);
    }
    attrSequence.end();
    opSequence.end();
  }


  public SearchRequest toSearchRequest(final Control... controls)
  {
    final String[] attrArray = new String[attributes.size()];
    attributes.toArray(attrArray);

    return new SearchRequest(null, controls, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attrArray);
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
    buffer.append("SearchRequestProtocolOp(baseDN='");
    buffer.append(baseDN);
    buffer.append("', scope='");
    buffer.append(scope.toString());
    buffer.append("', derefPolicy='");
    buffer.append(derefPolicy.toString());
    buffer.append("', sizeLimit=");
    buffer.append(sizeLimit);
    buffer.append(", timeLimit=");
    buffer.append(timeLimit);
    buffer.append(", typesOnly=");
    buffer.append(typesOnly);
    buffer.append(", filter='");
    filter.toString(buffer);
    buffer.append("', attributes={");

    final Iterator<String> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
