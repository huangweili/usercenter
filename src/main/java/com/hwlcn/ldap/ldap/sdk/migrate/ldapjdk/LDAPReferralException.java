package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.ldap.ldap.sdk.SearchResultReference;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPReferralException
       extends LDAPException
{

  private static final long serialVersionUID = 7867903105944011998L;


  private final String[] referralURLs;


  public LDAPReferralException()
  {
    super(null, REFERRAL);

    referralURLs = new String[0];
  }


  public LDAPReferralException(final String message, final int resultCode,
                               final String serverErrorMessage)
  {
    super(message, resultCode, serverErrorMessage, null);

    referralURLs = new String[0];
  }

  public LDAPReferralException(final String message, final int resultCode,
                               final String[] referrals)
  {
    super(message, resultCode, null, null);

    referralURLs = referrals;
  }


  public LDAPReferralException(
              final com.hwlcn.ldap.ldap.sdk.LDAPException ldapException)
  {
    super(ldapException);

    referralURLs = ldapException.getReferralURLs();
  }


  public LDAPReferralException(final SearchResultReference reference)
  {
    super(null, REFERRAL);

    referralURLs = reference.getReferralURLs();
  }


  public String[] getURLs()
  {
    return referralURLs;
  }
}
