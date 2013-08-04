
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.ldap.sdk.AsyncRequestID;
import com.hwlcn.ldap.ldap.sdk.AsyncSearchResultListener;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.ldap.ldap.sdk.SearchResultEntry;
import com.hwlcn.ldap.ldap.sdk.SearchResultReference;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;


@Mutable()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPSearchResults
       implements Enumeration<Object>, AsyncSearchResultListener
{

  private static final long serialVersionUID = 7884355145560496230L;

  private final AtomicBoolean searchDone;

  private final AtomicInteger count;

  private final AtomicReference<Control[]> lastControls;

  private final AtomicReference<Object> nextResult;

  private final AtomicReference<SearchResult> searchResult;

  private final long maxWaitTime;

  private final LinkedBlockingQueue<Object> resultQueue;


  public LDAPSearchResults()
  {
    this(0L);
  }


  public LDAPSearchResults(final long maxWaitTime)
  {
    this.maxWaitTime = maxWaitTime;

    searchDone   = new AtomicBoolean(false);
    count        = new AtomicInteger(0);
    lastControls = new AtomicReference<Control[]>();
    nextResult   = new AtomicReference<Object>();
    searchResult = new AtomicReference<SearchResult>();
    resultQueue  = new LinkedBlockingQueue<Object>(50);
  }



  private Object nextObject()
  {
    Object o = nextResult.get();
    if (o != null)
    {
      return o;
    }

    o = resultQueue.poll();
    if (o != null)
    {
      nextResult.set(o);
      return o;
    }

    if (searchDone.get())
    {
      return null;
    }

    try
    {
      if (maxWaitTime > 0)
      {
        o = resultQueue.poll(maxWaitTime, TimeUnit.MILLISECONDS);
        if (o == null)
        {
          o = new SearchResult(-1, ResultCode.TIMEOUT, null, null, null, 0, 0,
               null);
          count.incrementAndGet();
        }
      }
      else
      {
        o = resultQueue.take();
      }
    }
    catch (Exception e)
    {
      debugException(e);

      o = new SearchResult(-1, ResultCode.USER_CANCELED, null, null, null, 0, 0,
           null);
      count.incrementAndGet();
    }

    nextResult.set(o);
    return o;
  }



  public boolean hasMoreElements()
  {
    final Object o = nextObject();
    if (o == null)
    {
      return false;
    }

    if (o instanceof SearchResult)
    {
      final SearchResult r = (SearchResult) o;
      if (r.getResultCode().equals(ResultCode.SUCCESS))
      {
        lastControls.set(r.getResponseControls());
        searchDone.set(true);
        nextResult.set(null);
        return false;
      }
    }

    return true;
  }


  public Object nextElement()
         throws NoSuchElementException
  {
    final Object o = nextObject();
    if (o == null)
    {
      throw new NoSuchElementException();
    }

    nextResult.set(null);
    count.decrementAndGet();

    if (o instanceof SearchResultEntry)
    {
      final SearchResultEntry e = (SearchResultEntry) o;
      lastControls.set(e.getControls());
      return new LDAPEntry(e);
    }
    else if (o instanceof SearchResultReference)
    {
      final SearchResultReference r = (SearchResultReference) o;
      lastControls.set(r.getControls());
      return new LDAPReferralException(r);
    }
    else
    {
      final SearchResult r = (SearchResult) o;
      searchDone.set(true);
      nextResult.set(null);
      lastControls.set(r.getResponseControls());
      return new LDAPException(r.getDiagnosticMessage(),
           r.getResultCode().intValue(), r.getDiagnosticMessage(),
           r.getMatchedDN());
    }
  }


  public LDAPEntry next()
         throws LDAPException
  {
    if (! hasMoreElements())
    {
      throw new LDAPException(null, ResultCode.NO_RESULTS_RETURNED_INT_VALUE);
    }

    final Object o = nextElement();
    if (o instanceof LDAPEntry)
    {
      return (LDAPEntry) o;
    }

    throw (LDAPException) o;
  }



  public int getCount()
  {
    return count.get();
  }


  public LDAPControl[] getResponseControls()
  {
    final Control[] controls = lastControls.get();
    if ((controls == null) || (controls.length == 0))
    {
      return null;
    }

    return LDAPControl.toLDAPControls(controls);
  }



  @InternalUseOnly()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchEntry);
      count.incrementAndGet();
    }
    catch (Exception e)
    {
      debugException(e);
      searchDone.set(true);
    }
  }

  @InternalUseOnly()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchReference);
      count.incrementAndGet();
    }
    catch (Exception e)
    {
      debugException(e);
      searchDone.set(true);
    }
  }



  @InternalUseOnly()
  public void searchResultReceived(final AsyncRequestID requestID,
                                   final SearchResult searchResult)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchResult);
      if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        count.incrementAndGet();
      }
    }
    catch (Exception e)
    {
      debugException(e);
      searchDone.set(true);
    }
  }
}
