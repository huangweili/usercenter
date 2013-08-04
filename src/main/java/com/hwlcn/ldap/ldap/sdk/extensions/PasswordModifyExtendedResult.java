
package com.hwlcn.ldap.ldap.sdk.extensions;


import com.hwlcn.ldap.asn1.ASN1Element;
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



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordModifyExtendedResult
       extends ExtendedResult
{

  private static final long serialVersionUID = -160274020063799410L;
 private final ASN1OctetString generatedPassword;



  public PasswordModifyExtendedResult(final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      generatedPassword = null;
      return;
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_RESPONSE_VALUE_NOT_SEQUENCE.get(e),
                              e);
    }

    if (elements.length == 0)
    {
      generatedPassword = null;
      return;
    }
    else if (elements.length != 1)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_RESPONSE_MULTIPLE_ELEMENTS.get());
    }

    generatedPassword = ASN1OctetString.decodeAsOctetString(elements[0]);
  }


  public PasswordModifyExtendedResult(final int messageID,
                                      final ResultCode resultCode,
                                      final String diagnosticMessage,
                                      final String matchedDN,
                                      final String[] referralURLs,
                                      final ASN1OctetString generatedPassword,
                                      final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(generatedPassword), responseControls);

    this.generatedPassword = generatedPassword;
  }


  private static ASN1OctetString
          encodeValue(final ASN1OctetString generatedPassword)
  {
    if (generatedPassword == null)
    {
      return null;
    }

    final ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, generatedPassword.getValue())
    };

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }


  public String getGeneratedPassword()
  {
    if (generatedPassword == null)
    {
      return null;
    }
    else
    {
      return generatedPassword.stringValue();
    }
  }


  public byte[] getGeneratedPasswordBytes()
  {
    if (generatedPassword == null)
    {
      return null;
    }
    else
    {
      return generatedPassword.getValue();
    }
  }



  public ASN1OctetString getRawGeneratedPassword()
  {
    return generatedPassword;
  }



  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_PASSWORD_MODIFY.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordModifyExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (generatedPassword != null)
    {
      buffer.append(", generatedPassword='");
      buffer.append(generatedPassword.stringValue());
      buffer.append('\'');
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
