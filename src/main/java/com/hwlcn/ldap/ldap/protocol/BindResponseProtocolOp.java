package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.BindResult;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
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
public final class BindResponseProtocolOp
       implements ProtocolOp
{

  public static final byte TYPE_SERVER_SASL_CREDENTIALS = (byte) 0x87;




  private static final long serialVersionUID = -7757619031268544913L;



  private final ASN1OctetString serverSASLCredentials;

  private final int resultCode;

  private final List<String> referralURLs;

  private final String diagnosticMessage;

  private final String matchedDN;



  public BindResponseProtocolOp(final int resultCode, final String matchedDN,
                                final String diagnosticMessage,
                                final List<String> referralURLs,
                                final ASN1OctetString serverSASLCredentials)
  {
    this.resultCode            = resultCode;
    this.matchedDN             = matchedDN;
    this.diagnosticMessage     = diagnosticMessage;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }

    if (serverSASLCredentials == null)
    {
      this.serverSASLCredentials = null;
    }
    else
    {
      this.serverSASLCredentials = new ASN1OctetString(
           TYPE_SERVER_SASL_CREDENTIALS, serverSASLCredentials.getValue());
    }
  }

  public BindResponseProtocolOp(final LDAPResult result)
  {
    resultCode            = result.getResultCode().intValue();
    matchedDN             = result.getMatchedDN();
    diagnosticMessage     = result.getDiagnosticMessage();
    referralURLs          = toList(result.getReferralURLs());

    if (result instanceof BindResult)
    {
      final BindResult br = (BindResult) result;
      serverSASLCredentials = br.getServerSASLCredentials();
    }
    else
    {
      serverSASLCredentials = null;
    }
  }




  BindResponseProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      resultCode = reader.readEnumerated();

      String s = reader.readString();
      ensureNotNull(s);
      if (s.length() == 0)
      {
        matchedDN = null;
      }
      else
      {
        matchedDN = s;
      }

      s = reader.readString();
      ensureNotNull(s);
      if (s.length() == 0)
      {
        diagnosticMessage = null;
      }
      else
      {
        diagnosticMessage = s;
      }

      ASN1OctetString creds = null;
      final ArrayList<String> refs = new ArrayList<String>(1);
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        if (type == GenericResponseProtocolOp.TYPE_REFERRALS)
        {
          final ASN1StreamReaderSequence refSequence = reader.beginSequence();
          while (refSequence.hasMoreElements())
          {
            refs.add(reader.readString());
          }
        }
        else if (type == TYPE_SERVER_SASL_CREDENTIALS)
        {
          creds = new ASN1OctetString(type, reader.readBytes());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_RESPONSE_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      referralURLs = Collections.unmodifiableList(refs);
      serverSASLCredentials = creds;
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
           ERR_BIND_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public int getResultCode()
  {
    return resultCode;
  }



  public String getMatchedDN()
  {
    return matchedDN;
  }




  public String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }


  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  public ASN1OctetString getServerSASLCredentials()
  {
    return serverSASLCredentials;
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE;
  }

  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(5);
    elements.add(new ASN1Enumerated(getResultCode()));

    final String mDN = getMatchedDN();
    if (mDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(mDN));
    }

    final String dm = getDiagnosticMessage();
    if (dm == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(dm));
    }

    final List<String> refs = getReferralURLs();
    if (! refs.isEmpty())
    {
      final ArrayList<ASN1Element> refElements =
           new ArrayList<ASN1Element>(refs.size());
      for (final String r : refs)
      {
        refElements.add(new ASN1OctetString(r));
      }
      elements.add(new ASN1Sequence(GenericResponseProtocolOp.TYPE_REFERRALS,
           refElements));
    }

    if (serverSASLCredentials != null)
    {
      elements.add(serverSASLCredentials);
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE,
         elements);
  }


  public static BindResponseProtocolOp decodeProtocolOp(
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

      ASN1OctetString serverSASLCredentials = null;
      List<String> referralURLs = null;
      if (elements.length > 3)
      {
        for (int i=3; i < elements.length; i++)
        {
          switch (elements[i].getType())
          {
            case GenericResponseProtocolOp.TYPE_REFERRALS:
              final ASN1Element[] refElements =
                   ASN1Sequence.decodeAsSequence(elements[3]).elements();
              referralURLs = new ArrayList<String>(refElements.length);
              for (final ASN1Element e : refElements)
              {
                referralURLs.add(
                     ASN1OctetString.decodeAsOctetString(e).stringValue());
              }
              break;

            case TYPE_SERVER_SASL_CREDENTIALS:
              serverSASLCredentials =
                   ASN1OctetString.decodeAsOctetString(elements[i]);
              break;

            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_BIND_RESPONSE_INVALID_ELEMENT.get(
                        toHex(elements[i].getType())));
          }
        }
      }

      return new BindResponseProtocolOp(resultCode, matchedDN,
           diagnosticMessage, referralURLs, serverSASLCredentials);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_BIND_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE);
    buffer.addEnumerated(resultCode);
    buffer.addOctetString(matchedDN);
    buffer.addOctetString(diagnosticMessage);

    if (! referralURLs.isEmpty())
    {
      final ASN1BufferSequence refSequence =
           buffer.beginSequence(GenericResponseProtocolOp.TYPE_REFERRALS);
      for (final String s : referralURLs)
      {
        buffer.addOctetString(s);
      }
      refSequence.end();
    }

    if (serverSASLCredentials != null)
    {
      buffer.addElement(serverSASLCredentials);
    }

    opSequence.end();
  }



  public BindResult toBindResult(final Control... controls)
  {
    final String[] refs;
    if (referralURLs.isEmpty())
    {
      refs = NO_STRINGS;
    }
    else
    {
      refs = new String[referralURLs.size()];
      referralURLs.toArray(refs);
    }

    return new BindResult(-1, ResultCode.valueOf(resultCode), diagnosticMessage,
         matchedDN, refs, controls, serverSASLCredentials);
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
    buffer.append("BindResponseProtocolOp(resultCode=");
    buffer.append(resultCode);

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (! referralURLs.isEmpty())
    {
      buffer.append(", referralURLs={");

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

      buffer.append('}');
    }
    buffer.append(')');
  }
}
