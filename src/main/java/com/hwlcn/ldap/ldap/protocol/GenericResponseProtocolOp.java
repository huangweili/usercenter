package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class GenericResponseProtocolOp
       implements ProtocolOp
{

  public static final byte TYPE_REFERRALS = (byte) 0xA3;

  private static final long serialVersionUID = 3837308973105414874L;

  private final byte type;

  private final int resultCode;

  private final List<String> referralURLs;

  private final String diagnosticMessage;

  private final String matchedDN;


  protected GenericResponseProtocolOp(final byte type, final int resultCode,
                                    final String matchedDN,
                                    final String diagnosticMessage,
                                    final List<String> referralURLs)
  {
    this.type              = type;
    this.resultCode        = resultCode;
    this.matchedDN         = matchedDN;
    this.diagnosticMessage = diagnosticMessage;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }
  }



  protected GenericResponseProtocolOp(final ASN1StreamReader reader)
            throws LDAPException
  {
    try
    {
      type = (byte) reader.peek();
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

      if (opSequence.hasMoreElements())
      {
        final ArrayList<String> refs = new ArrayList<String>(1);
        final ASN1StreamReaderSequence refSequence = reader.beginSequence();
        while (refSequence.hasMoreElements())
        {
          refs.add(reader.readString());
        }
        referralURLs = Collections.unmodifiableList(refs);
      }
      else
      {
        referralURLs = Collections.emptyList();
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public final int getResultCode()
  {
    return resultCode;
  }


  public final String getMatchedDN()
  {
    return matchedDN;
  }

  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }

  public final List<String> getReferralURLs()
  {
    return referralURLs;
  }


  public byte getProtocolOpType()
  {
    return type;
  }


  public final void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence = buffer.beginSequence(type);
    buffer.addEnumerated(resultCode);
    buffer.addOctetString(matchedDN);
    buffer.addOctetString(diagnosticMessage);

    if (! referralURLs.isEmpty())
    {
      final ASN1BufferSequence refSequence =
           buffer.beginSequence(TYPE_REFERRALS);
      for (final String s : referralURLs)
      {
        buffer.addOctetString(s);
      }
      refSequence.end();
    }
    opSequence.end();
  }


  public LDAPResult toLDAPResult(final Control... controls)
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

    return new LDAPResult(-1, ResultCode.valueOf(resultCode), diagnosticMessage,
         matchedDN, refs, controls);
  }



  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  public final void toString(final StringBuilder buffer)
  {
    buffer.append("ResponseProtocolOp(type=");
    toHex(type, buffer);
    buffer.append(", resultCode=");
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
