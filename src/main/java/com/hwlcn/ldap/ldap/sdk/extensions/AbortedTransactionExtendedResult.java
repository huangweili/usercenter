package com.hwlcn.ldap.ldap.sdk.extensions;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AbortedTransactionExtendedResult
       extends ExtendedResult
{

  public static final String ABORTED_TRANSACTION_RESULT_OID = "1.3.6.1.1.21.4";

  private static final long serialVersionUID = 7521522597566232465L;

  private final ASN1OctetString transactionID;

  public AbortedTransactionExtendedResult(final ASN1OctetString transactionID,
                                          final ResultCode resultCode,
                                          final String diagnosticMessage,
                                          final String matchedDN,
                                          final String[] referralURLs,
                                          final Control[] controls)
  {
    super(0, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ABORTED_TRANSACTION_RESULT_OID, transactionID, controls);

    ensureNotNull(transactionID, resultCode);

    this.transactionID = transactionID;
  }

  public AbortedTransactionExtendedResult(final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    transactionID = extendedResult.getValue();
    if (transactionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABORTED_TXN_NO_VALUE.get());
    }
  }

  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }

  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_ABORTED_TXN.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AbortedTransactionExtendedResult(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("', resultCode=");
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
    buffer.append(ABORTED_TRANSACTION_RESULT_OID);

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
