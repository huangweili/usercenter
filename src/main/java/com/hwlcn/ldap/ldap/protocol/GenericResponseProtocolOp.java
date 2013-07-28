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
  /**
   * The BER type for the referral URLs elements.
   */
  public static final byte TYPE_REFERRALS = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3837308973105414874L;



  // The BER type for this response.
  private final byte type;

  // The result code for this response.
  private final int resultCode;

  // The referral URLs for this response.
  private final List<String> referralURLs;

  // The diagnostic message for this response.
  private final String diagnosticMessage;

  // The matched DN for this response.Static
  private final String matchedDN;



  /**
   * Creates a new instance of this response with the provided information.
   *
   * @param  type               The BER type for this response.
   * @param  resultCode         The result code for this response.
   * @param  matchedDN          The matched DN for this result, if available.
   * @param  diagnosticMessage  The diagnostic message for this response, if
   *                            available.
   * @param  referralURLs       The list of referral URLs for this response, if
   *                            available.
   */
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



  /**
   * Creates a new response read from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the response.
   *
   * @throws  com.hwlcn.ldap.ldap.sdk.LDAPException  If a problem occurs while reading or parsing the
   *                         response.
   */
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



  /**
   * Retrieves the result code for this response.
   *
   * @return  The result code for this response.
   */
  public final int getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the matched DN for this response, if any.
   *
   * @return  The matched DN for this response, or {@code null} if there is
   *          no matched DN.
   */
  public final String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the diagnostic message for this response, if any.
   *
   * @return  The diagnostic message for this response, or {@code null} if there
   *          is no diagnostic message.
   */
  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the list of referral URLs for this response.
   *
   * @return  The list of referral URLs for this response, or an empty list
   *          if there are no referral URLs.
   */
  public final List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return type;
  }



  /**
   * {@inheritDoc}
   */
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



  /**
   * Creates a new LDAP result object from this response protocol op.
   *
   * @param  controls  The set of controls to include in the LDAP result.  It
   *                   may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The LDAP result that was created.
   */
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



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
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
