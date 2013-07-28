package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
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
public class LDAPResult
       implements Serializable, LDAPResponse
{
  static final byte TYPE_REFERRAL_URLS = (byte) 0xA3;



  private static final long serialVersionUID = 2215819095653175991L;



  private final Byte protocolOpType;

  private final Control[] responseControls;

  private final int messageID;

  private final ResultCode resultCode;

  private final String diagnosticMessage;

  private final String matchedDN;

  private final String[] referralURLs;

  protected LDAPResult(final LDAPResult result)
  {
    protocolOpType    = result.protocolOpType;
    messageID         = result.messageID;
    resultCode        = result.resultCode;
    diagnosticMessage = result.diagnosticMessage;
    matchedDN         = result.matchedDN;
    referralURLs      = result.referralURLs;
    responseControls  = result.responseControls;
  }


  public LDAPResult(final int messageID, final ResultCode resultCode)
  {
    this(null, messageID, resultCode, null, null, NO_STRINGS, NO_CONTROLS);
  }

  public LDAPResult(final int messageID, final ResultCode resultCode,
                    final String diagnosticMessage, final String matchedDN,
                    final String[] referralURLs,
                    final Control[] responseControls)
  {
    this(null, messageID, resultCode, diagnosticMessage, matchedDN,
         referralURLs, responseControls);
  }


    public LDAPResult(final int messageID, final ResultCode resultCode,
                    final String diagnosticMessage, final String matchedDN,
                    final List<String> referralURLs,
                    final List<Control> responseControls)
  {
    this(null, messageID, resultCode, diagnosticMessage, matchedDN,
         referralURLs, responseControls);
  }


  private LDAPResult(final Byte protocolOpType, final int messageID,
                     final ResultCode resultCode,
                     final String diagnosticMessage, final String matchedDN,
                     final String[] referralURLs,
                     final Control[] responseControls)
  {
    this.protocolOpType    = protocolOpType;
    this.messageID         = messageID;
    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = NO_STRINGS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    if (responseControls == null)
    {
      this.responseControls = NO_CONTROLS;
    }
    else
    {
      this.responseControls = responseControls;
    }
  }


  private LDAPResult(final Byte protocolOpType, final int messageID,
                     final ResultCode resultCode,
                     final String diagnosticMessage, final String matchedDN,
                     final List<String> referralURLs,
                     final List<Control> responseControls)
  {
    this.protocolOpType    = protocolOpType;
    this.messageID         = messageID;
    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if ((referralURLs == null) || referralURLs.isEmpty())
    {
      this.referralURLs = NO_STRINGS;
    }
    else
    {
      this.referralURLs = new String[referralURLs.size()];
      referralURLs.toArray(this.referralURLs);
    }

    if ((responseControls == null) || responseControls.isEmpty())
    {
      this.responseControls = NO_CONTROLS;
    }
    else
    {
      this.responseControls = new Control[responseControls.size()];
      responseControls.toArray(this.responseControls);
    }
  }


  static LDAPResult readLDAPResultFrom(final int messageID,
                         final ASN1StreamReaderSequence messageSequence,
                         final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence protocolOpSequence =
           reader.beginSequence();
      final byte protocolOpType = protocolOpSequence.getType();

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

      String[] referralURLs = NO_STRINGS;
      if (protocolOpSequence.hasMoreElements())
      {
        final ArrayList<String> refList = new ArrayList<String>(1);
        final ASN1StreamReaderSequence refSequence = reader.beginSequence();
        while (refSequence.hasMoreElements())
        {
          refList.add(reader.readString());
        }

        referralURLs = new String[refList.size()];
        refList.toArray(referralURLs);
      }

      Control[] responseControls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        responseControls = new Control[controlList.size()];
        controlList.toArray(responseControls);
      }

      return new LDAPResult(protocolOpType, messageID, resultCode,
           diagnosticMessage, matchedDN, referralURLs, responseControls);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESULT_CANNOT_DECODE.get(ae.getMessage()), ae);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RESULT_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public final int getMessageID()
  {
    return messageID;
  }


  public final ResultCode getResultCode()
  {
    return resultCode;
  }



  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }

  public final String getMatchedDN()
  {
    return matchedDN;
  }

  public final String[] getReferralURLs()
  {
    return referralURLs;
  }

  public final Control[] getResponseControls()
  {
    return responseControls;
  }

  public final boolean hasResponseControl()
  {
    return (responseControls.length > 0);
  }

  public final boolean hasResponseControl(final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return true;
      }
    }

    return false;
  }

  public final Control getResponseControl(final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
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
    buffer.append("LDAPResult(resultCode=");
    buffer.append(resultCode);

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (protocolOpType != null)
    {
      switch (protocolOpType)
      {
        case LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE:
          buffer.append(", opType='add'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE:
          buffer.append(", opType='bind'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          buffer.append(", opType='compare'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          buffer.append(", opType='delete'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          buffer.append(", opType='extended'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          buffer.append(", opType='modify'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          buffer.append(", opType='modify DN'");
          break;
        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          buffer.append(", opType='search'");
          break;
      }
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

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
