package com.hwlcn.ldap.ldap.sdk.extensions;


import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class WhoAmIExtendedResult
       extends ExtendedResult
{

  private static final long serialVersionUID = 7466531316632846077L;

  private final String authorizationID;

  public WhoAmIExtendedResult(final ExtendedResult extendedResult)
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      authorizationID = null;
    }
    else
    {
      authorizationID = value.stringValue();
    }
  }

  public WhoAmIExtendedResult(final int messageID, final ResultCode resultCode,
                              final String diagnosticMessage,
                              final String matchedDN,
                              final String[] referralURLs,
                              final String authorizationID,
                              final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(authorizationID), responseControls);

    this.authorizationID = authorizationID;
  }


  private static ASN1OctetString encodeValue(final String authorizationID)
  {
    if (authorizationID == null)
    {
      return null;
    }
    else
    {
      return new ASN1OctetString(authorizationID);
    }
  }

  public String getAuthorizationID()
  {
    return authorizationID;
  }

  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_WHO_AM_I.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("WhoAmIExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
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
