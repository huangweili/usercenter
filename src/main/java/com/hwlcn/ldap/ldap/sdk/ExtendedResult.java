package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ExtendedResult
       extends LDAPResult
{

  private static final byte TYPE_EXTENDED_RESPONSE_OID = (byte) 0x8A;


  private static final byte TYPE_EXTENDED_RESPONSE_VALUE = (byte) 0x8B;

  private static final long serialVersionUID = -6885923482396647963L;

  private final ASN1OctetString value;

  private final String oid;


 public ExtendedResult(final int messageID, final ResultCode resultCode,
                        final String diagnosticMessage, final String matchedDN,
                        final String[] referralURLs, final String oid,
                        final ASN1OctetString value,
                        final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.oid   = oid;
    this.value = value;
  }



  public ExtendedResult(final LDAPResult result)
  {
    super(result);

    oid   = null;
    value = null;
  }



  protected ExtendedResult(final ExtendedResult extendedResult)
  {
    this(extendedResult.getMessageID(), extendedResult.getResultCode(),
         extendedResult.getDiagnosticMessage(), extendedResult.getMatchedDN(),
         extendedResult.getReferralURLs(), extendedResult.getOID(),
         extendedResult.getValue(), extendedResult.getResponseControls());
  }




  static ExtendedResult readExtendedResultFrom(final int messageID,
                             final ASN1StreamReaderSequence messageSequence,
                             final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence protocolOpSequence =
           reader.beginSequence();
      final ResultCode resultCode = ResultCode.valueOf(reader.readEnumerated());

      String matchedDN = reader.readString();
      if (matchedDN.length() == 0)
      {
        matchedDN = null;
      }

      String diagnosticMessage = reader.readString();
      if (diagnosticMessage.length() == 0)
      {
        diagnosticMessage = null;
      }

      String[] referralURLs = null;
      String oid = null;
      ASN1OctetString value = null;
      while (protocolOpSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case TYPE_REFERRAL_URLS:
            final ArrayList<String> refList = new ArrayList<String>(1);
            final ASN1StreamReaderSequence refSequence = reader.beginSequence();
            while (refSequence.hasMoreElements())
            {
              refList.add(reader.readString());
            }
            referralURLs = new String[refList.size()];
            refList.toArray(referralURLs);
            break;

          case TYPE_EXTENDED_RESPONSE_OID:
            oid = reader.readString();
            break;

          case TYPE_EXTENDED_RESPONSE_VALUE:
            value = new ASN1OctetString(type, reader.readBytes());
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_EXTENDED_RESULT_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      Control[] controls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }

      return new ExtendedResult(messageID, resultCode, diagnosticMessage,
                                matchedDN, referralURLs, oid, value, controls);
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
           ERR_EXTENDED_RESULT_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }




  public final String getOID()
  {
    return oid;
  }



  public final boolean hasValue()
  {
    return (value != null);
  }



  public final ASN1OctetString getValue()
  {
    return value;
  }




  public String getExtendedResultName()
  {

    return oid;
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
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

        buffer.append(referralURLs[i]);
      }
      buffer.append('}');
    }

    if (oid != null)
    {
      buffer.append(", oid=");
      buffer.append(oid);
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
