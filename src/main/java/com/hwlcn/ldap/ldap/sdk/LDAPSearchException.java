package com.hwlcn.ldap.ldap.sdk;

import java.util.List;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSearchException
       extends LDAPException
{
  private static final long serialVersionUID = 350230437196125113L;

  private final SearchResult searchResult;

  public LDAPSearchException(final ResultCode resultCode,
                             final String errorMessage)
  {
    super(resultCode, errorMessage);

    searchResult = new SearchResult(-1, resultCode, errorMessage, null,
         StaticUtils.NO_STRINGS, 0, 0, StaticUtils.NO_CONTROLS);
  }

  public LDAPSearchException(final ResultCode resultCode,
                             final String errorMessage, final Throwable cause)
  {
    super(resultCode, errorMessage, cause);

    searchResult = new SearchResult(-1, resultCode, errorMessage, null,
         StaticUtils.NO_STRINGS , 0, 0, StaticUtils.NO_CONTROLS);
  }

  public LDAPSearchException(final LDAPException ldapException)
  {
    super(ldapException.getResultCode(), ldapException.getMessage(),
          ldapException.getMatchedDN(), ldapException.getReferralURLs(),
          ldapException.getResponseControls(), ldapException);

    if (ldapException instanceof LDAPSearchException)
    {
      final LDAPSearchException lse = (LDAPSearchException) ldapException;
      searchResult = lse.searchResult;
    }
    else
    {
      searchResult = new SearchResult(-1, ldapException.getResultCode(),
                                      ldapException.getMessage(),
                                      ldapException.getMatchedDN(),
                                      ldapException.getReferralURLs(), 0, 0,
                                      ldapException.getResponseControls());
    }
  }

  public LDAPSearchException(final SearchResult searchResult)
  {
    super(searchResult);

    this.searchResult = searchResult;
  }

  public SearchResult getSearchResult()
  {
    return searchResult;
  }

  public int getEntryCount()
  {
    return searchResult.getEntryCount();
  }

  public int getReferenceCount()
  {
    return searchResult.getReferenceCount();
  }

  public List<SearchResultEntry> getSearchEntries()
  {
    return searchResult.getSearchEntries();
  }

  public List<SearchResultReference> getSearchReferences()
  {
    return searchResult.getSearchReferences();
  }

  @Override()
  public SearchResult toLDAPResult()
  {
    return searchResult;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPSearchException(resultCode=");
    buffer.append(getResultCode());
    buffer.append(", numEntries=");
    buffer.append(searchResult.getEntryCount());
    buffer.append(", numReferences=");
    buffer.append(searchResult.getReferenceCount());

    final String errorMessage = getMessage();
    if (errorMessage != null)
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
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
