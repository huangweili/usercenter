package com.hwlcn.ldap.ldap.sdk.extensions;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NoticeOfDisconnectionExtendedResult
       extends ExtendedResult
{

  public static final String NOTICE_OF_DISCONNECTION_RESULT_OID =
       "1.3.6.1.4.1.1466.20036";

  private static final long serialVersionUID = -4706102471360689558L;

  public NoticeOfDisconnectionExtendedResult(
              final ExtendedResult extendedResult)
  {
    super(extendedResult);
  }

  public NoticeOfDisconnectionExtendedResult(
              final int messageID, final ResultCode resultCode,
              final String diagnosticMessage, final String matchedDN,
              final String[] referralURLs, final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          NOTICE_OF_DISCONNECTION_RESULT_OID, null, responseControls);
  }

  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_NOTICE_OF_DISCONNECT.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("NoticeOfDisconnectionExtendedResult(resultCode=");
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

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    buffer.append(", oid=");
    buffer.append(NOTICE_OF_DISCONNECTION_RESULT_OID);

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
