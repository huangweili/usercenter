package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareResult
       extends LDAPResult
{
  private static final long serialVersionUID = -6061844770039020617L;



  public CompareResult(final LDAPResult ldapResult)
  {
    super(ldapResult);
  }



  public CompareResult(final int messageID, final ResultCode resultCode,
                       final String diagnosticMessage, final String matchedDN,
                       final String[] referralURLs,
                       final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);
  }



  static CompareResult readCompareResultFrom(final int messageID,
                            final ASN1StreamReaderSequence messageSequence,
                            final ASN1StreamReader reader)
         throws LDAPException
  {
    return new CompareResult(LDAPResult.readLDAPResultFrom(messageID,
                    messageSequence, reader));
  }


  public boolean compareMatched()
  {
    return (getResultCode().equals(ResultCode.COMPARE_TRUE));
  }
}
