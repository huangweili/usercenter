package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;




@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BasicAsyncSearchResultListener
       implements AsyncSearchResultListener
{

  private static final long serialVersionUID = 2289128360755244209L;



  private final List<SearchResultEntry> entryList;

  private final List<SearchResultReference> referenceList;

  private volatile SearchResult searchResult;




  public BasicAsyncSearchResultListener()
  {
    searchResult  = null;
    entryList     = new ArrayList<SearchResultEntry>(5);
    referenceList = new ArrayList<SearchResultReference>(5);
  }


  @InternalUseOnly()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    entryList.add(searchEntry);
  }



  @InternalUseOnly()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    referenceList.add(searchReference);
  }




  @InternalUseOnly()
  public void searchResultReceived(final AsyncRequestID requestID,
                                    final SearchResult searchResult)
  {
    this.searchResult = searchResult;
  }




  public SearchResult getSearchResult()
  {
    return searchResult;
  }




  public List<SearchResultEntry> getSearchEntries()
  {
    return Collections.unmodifiableList(entryList);
  }



  public List<SearchResultReference> getSearchReferences()
  {
    return Collections.unmodifiableList(referenceList);
  }
}
