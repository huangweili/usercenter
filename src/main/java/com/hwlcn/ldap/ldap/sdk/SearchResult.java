package com.hwlcn.ldap.ldap.sdk;



import java.util.Collections;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResult
       extends LDAPResult
{

  private static final long serialVersionUID = 1938208530894131198L;

  private int numEntries;
  private int numReferences;
  private List<SearchResultEntry> searchEntries;

  private List<SearchResultReference> searchReferences;



  public SearchResult(final int messageID, final ResultCode resultCode,
                      final String diagnosticMessage, final String matchedDN,
                      final String[] referralURLs, final int numEntries,
                      final int numReferences, final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.numEntries    = numEntries;
    this.numReferences = numReferences;

    searchEntries    = null;
    searchReferences = null;
  }


  public SearchResult(final int messageID, final ResultCode resultCode,
                      final String diagnosticMessage, final String matchedDN,
                      final String[] referralURLs,
                      final List<SearchResultEntry> searchEntries,
                      final List<SearchResultReference> searchReferences,
                      final int numEntries, final int numReferences,
                      final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.numEntries       = numEntries;
    this.numReferences    = numReferences;
    this.searchEntries    = searchEntries;
    this.searchReferences = searchReferences;
  }



  static SearchResult readSearchResultFrom(final int messageID,
                           final ASN1StreamReaderSequence messageSequence,
                           final ASN1StreamReader reader)
         throws LDAPException
  {
    final LDAPResult r =
         LDAPResult.readLDAPResultFrom(messageID, messageSequence, reader);

    return new SearchResult(messageID, r.getResultCode(),
         r.getDiagnosticMessage(), r.getMatchedDN(), r.getReferralURLs(),
         -1, -1, r.getResponseControls());
  }


  public int getEntryCount()
  {
    return numEntries;
  }

  public int getReferenceCount()
  {
    return numReferences;
  }


  public List<SearchResultEntry> getSearchEntries()
  {
    if (searchEntries == null)
    {
      return null;
    }

    return Collections.unmodifiableList(searchEntries);
  }


  public SearchResultEntry getSearchEntry(final String dn)
         throws LDAPException
  {
    if (searchEntries == null)
    {
      return null;
    }

    final DN parsedDN = new DN(dn);
    for (final SearchResultEntry e : searchEntries)
    {
      if (parsedDN.equals(e.getParsedDN()))
      {
        return e;
      }
    }

    return null;
  }



  public List<SearchResultReference> getSearchReferences()
  {
    if (searchReferences == null)
    {
      return null;
    }

    return Collections.unmodifiableList(searchReferences);
  }


  void setCounts(final int numEntries,
                 final List<SearchResultEntry> searchEntries,
                 final int numReferences,
                 final List<SearchResultReference> searchReferences)
  {
    this.numEntries    = numEntries;
    this.numReferences = numReferences;

    if (searchEntries == null)
    {
      this.searchEntries = null;
    }
    else
    {
      this.searchEntries = Collections.unmodifiableList(searchEntries);
    }

    if (searchReferences == null)
    {
      this.searchReferences = null;
    }
    else
    {
      this.searchReferences = Collections.unmodifiableList(searchReferences);
    }
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchResult(resultCode=");
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

    buffer.append(", entriesReturned=");
    buffer.append(numEntries);
    buffer.append(", referencesReturned=");
    buffer.append(numReferences);

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
