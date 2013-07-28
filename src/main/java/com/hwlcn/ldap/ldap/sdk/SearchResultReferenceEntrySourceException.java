package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReferenceEntrySourceException
       extends EntrySourceException
{

  private static final long serialVersionUID = 4389660042011914324L;


  private final SearchResultReference searchReference;



  public SearchResultReferenceEntrySourceException(
              final SearchResultReference searchReference)
  {
    super(true, new LDAPException(ResultCode.REFERRAL, null, null,
         searchReference.getReferralURLs(), searchReference.getControls(),
         null));

    this.searchReference = searchReference;
  }



  public SearchResultReference getSearchReference()
  {
    return searchReference;
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchResultReferenceEntrySourceException(searchReference=");
    searchReference.toString(buffer);
    buffer.append("')");
  }
}
