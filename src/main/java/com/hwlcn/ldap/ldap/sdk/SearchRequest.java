package com.hwlcn.ldap.ldap.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.ProtocolOp;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 search
 * operation, which can be used to retrieve entries that match a given set of
 * criteria.  A search request may include the following elements:
 * <UL>
 *   <LI>Base DN -- Specifies the base DN for the search.  Only entries at or
 *       below this location in the server (based on the scope) will be
 *       considered potential matches.</LI>
 *   <LI>Scope -- Specifies the range of entries relative to the base DN that
 *       may be considered potential matches.</LI>
 *   <LI>Dereference Policy -- Specifies the behavior that the server should
 *       exhibit if any alias entries are encountered while processing the
 *       search.  If no dereference policy is provided, then a default of
 *       {@code DereferencePolicy.NEVER} will be used.</LI>
 *   <LI>Size Limit -- Specifies the maximum number of entries that should be
 *       returned from the search.  A value of zero indicates that there should
 *       not be any limit enforced.  Note that the directory server may also
 *       be configured with a server-side size limit which can also limit the
 *       number of entries that may be returned to the client and in that case
 *       the smaller of the client-side and server-side limits will be
 *       used.  If no size limit is provided, then a default of zero (unlimited)
 *       will be used.</LI>
 *   <LI>Time Limit -- Specifies the maximum length of time in seconds that the
 *       server should spend processing the search.  A value of zero indicates
 *       that there should not be any limit enforced.  Note that the directory
 *       server may also be configured with a server-side time limit which can
 *       also limit the processing time, and in that case the smaller of the
 *       client-side and server-side limits will be used.  If no time limit is
 *       provided, then a default of zero (unlimited) will be used.</LI>
 *   <LI>Types Only -- Indicates whether matching entries should include only
 *       attribute names, or both attribute names and values.  If no value is
 *       provided, then a default of {@code false} will be used.</LI>
 *   <LI>Filter -- Specifies the criteria for determining which entries should
 *       be returned.  See the {@link com.hwlcn.ldap.ldap.sdk.Filter} class for the types of filters
 *       that may be used.
 *       <BR><BR>
 *       Note that filters can be specified using either their string
 *       representations or as {@link com.hwlcn.ldap.ldap.sdk.Filter} objects.  As noted in the
 *       documentation for the {@link com.hwlcn.ldap.ldap.sdk.Filter} class, using the string
 *       representation may be somewhat dangerous if the data is not properly
 *       sanitized because special characters contained in the filter may cause
 *       it to be invalid or worse expose a vulnerability that could cause the
 *       filter to request more information than was intended.  As a result, if
 *       the filter may include special characters or user-provided strings,
 *       then it is recommended that you use {@link com.hwlcn.ldap.ldap.sdk.Filter} objects created from
 *       their individual components rather than their string representations.
 * </LI>
 *   <LI>Attributes -- Specifies the set of attributes that should be included
 *       in matching entries.  If no attributes are provided, then the server
 *       will default to returning all user attributes.  If a specified set of
 *       attributes is given, then only those attributes will be included.
 *       Values that may be included to indicate a special meaning include:
 *       <UL>
 *         <LI>{@code NO_ATTRIBUTES} -- Indicates that no attributes should be
 *             returned.  That is, only the DNs of matching entries will be
 *             returned.</LI>
 *         <LI>{@code ALL_USER_ATTRIBUTES} -- Indicates that all user attributes
 *             should be included in matching entries.  This is the default if
 *             no attributes are provided, but this special value may be
 *             included if a specific set of operational attributes should be
 *             included along with all user attributes.</LI>
 *         <LI>{@code ALL_OPERATIONAL_ATTRIBUTES} -- Indicates that all
 *             operational attributes should be included in matching
 *             entries.</LI>
 *       </UL>
 *       These special values may be used alone or in conjunction with each
 *       other and/or any specific attribute names or OIDs.</LI>
 *   <LI>An optional set of controls to include in the request to send to the
 *       server.</LI>
 *   <LI>An optional {@link SearchResultListener} which may be used to process
 *       search result entries and search result references returned by the
 *       server in the course of processing the request.  If this is
 *       {@code null}, then the entries and references will be collected and
 *       returned in the {@link com.hwlcn.ldap.ldap.sdk.SearchResult} object that is returned.</LI>
 * </UL>
 * When processing a search operation, there are three ways that the returned
 * entries and references may be accessed:
 * <UL>
 *   <LI>If the {@link com.hwlcn.ldap.ldap.sdk.LDAPInterface#search(com.hwlcn.ldap.ldap.sdk.SearchRequest)} method is used and
 *       the provided search request does not include a
 *       {@link SearchResultListener} object, then the entries and references
 *       will be collected internally and made available in the
 *       {@link com.hwlcn.ldap.ldap.sdk.SearchResult} object that is returned.</LI>
 *   <LI>If the {@link com.hwlcn.ldap.ldap.sdk.LDAPInterface#search(com.hwlcn.ldap.ldap.sdk.SearchRequest)} method is used and
 *       the provided search request does include a {@link SearchResultListener}
 *       object, then that listener will be used to provide access to the
 *       entries and references, and they will not be present in the
 *       {@link com.hwlcn.ldap.ldap.sdk.SearchResult} object (although the number of entries and
 *       references returned will still be available).</LI>
 *   <LI>The {@link LDAPEntrySource} object may be used to access the entries
 *        and references returned from the search.  It uses an
 *        {@code Iterator}-like API to provide access to the entries that are
 *        returned, and any references returned will be included in the
 *        {@link EntrySourceException} thrown on the appropriate call to
 *        {@link LDAPEntrySource#nextEntry()}.</LI>
 * </UL>
 * <BR><BR>
 * {@code SearchRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code SearchRequest}
 * objects are not threadsafe and therefore a single {@code SearchRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates a simple search operation in which the
 * client performs a search to find all users in the "Sales" department and then
 * prints out the name and e-mail address for each matching user:
 * <PRE>
 *   Filter filter = Filter.createEqualityFilter("ou", "Sales");
 *
 *   SearchRequest searchRequest =
 *        new SearchRequest("dc=example,dc=com", SearchScope.SUB, filter,
 *                          "cn", "mail");
 *
 *   try
 *   {
 *     SearchResult searchResult = connection.search(searchRequest);
 *
 *     for (SearchResultEntry entry : searchResult.getSearchEntries())
 *     {
 *       String name = entry.getAttributeValue("cn");
 *       String mail = entry.getAttributeValue("mail");
 *       System.out.println(name + "\t" + mail);
 *     }
 *   }
 *   catch (LDAPSearchException lse)
 *   {
 *     System.err.println("The search failed.");
 *   }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SearchRequest
       extends UpdatableLDAPRequest
       implements ReadOnlySearchRequest, ResponseAcceptor, ProtocolOp
{

  public static final String ALL_USER_ATTRIBUTES = "*";


  public static final String ALL_OPERATIONAL_ATTRIBUTES = "+";



  public static final String NO_ATTRIBUTES = "1.1";




  public static final String[] REQUEST_ATTRS_DEFAULT = NO_STRINGS;


  private static final long serialVersionUID = 1500219434086474893L;



  private String[] attributes;

  private boolean typesOnly;

  private DereferencePolicy derefPolicy;

  private int messageID = -1;

  private int sizeLimit;

  private int timeLimit;

  private Filter filter;


  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>(50);

  private final SearchResultListener searchResultListener;

  private SearchScope scope;

  private String baseDN;



  public SearchRequest(final String baseDN, final SearchScope scope,
                       final String filter, final String... attributes)
         throws LDAPException
  {
    this(null, null, baseDN, scope, DereferencePolicy.NEVER, 0, 0, false,
         Filter.create(filter), attributes);
  }



  public SearchRequest(final String baseDN, final SearchScope scope,
                       final Filter filter, final String... attributes)
  {
    this(null, null, baseDN, scope, DereferencePolicy.NEVER, 0, 0, false,
         filter, attributes);
  }




  public SearchRequest(final SearchResultListener searchResultListener,
                       final String baseDN, final SearchScope scope,
                       final String filter, final String... attributes)
         throws LDAPException
  {
    this(searchResultListener, null, baseDN, scope, DereferencePolicy.NEVER, 0,
         0, false, Filter.create(filter), attributes);
  }



  public SearchRequest(final SearchResultListener searchResultListener,
                       final String baseDN, final SearchScope scope,
                       final Filter filter, final String... attributes)
  {
    this(searchResultListener, null, baseDN, scope, DereferencePolicy.NEVER, 0,
         0, false, filter, attributes);
  }



  public SearchRequest(final String baseDN, final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final String filter, final String... attributes)
         throws LDAPException
  {
    this(null, null, baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, Filter.create(filter), attributes);
  }


  public SearchRequest(final String baseDN, final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final Filter filter, final String... attributes)
  {
    this(null, null, baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, filter, attributes);
  }



  public SearchRequest(final SearchResultListener searchResultListener,
                       final String baseDN, final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final String filter, final String... attributes)
         throws LDAPException
  {
    this(searchResultListener, null, baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, Filter.create(filter), attributes);
  }



  public SearchRequest(final SearchResultListener searchResultListener,
                       final String baseDN, final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final Filter filter, final String... attributes)
  {
    this(searchResultListener, null, baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, filter, attributes);
  }




  public SearchRequest(final SearchResultListener searchResultListener,
                       final Control[] controls, final String baseDN,
                       final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final String filter, final String... attributes)
         throws LDAPException
  {
    this(searchResultListener, controls, baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, Filter.create(filter), attributes);
  }


  public SearchRequest(final SearchResultListener searchResultListener,
                       final Control[] controls, final String baseDN,
                       final SearchScope scope,
                       final DereferencePolicy derefPolicy, final int sizeLimit,
                       final int timeLimit, final boolean typesOnly,
                       final Filter filter, final String... attributes)
  {
    super(controls);

    ensureNotNull(baseDN, filter);

    this.baseDN               = baseDN;
    this.scope                = scope;
    this.derefPolicy          = derefPolicy;
    this.typesOnly            = typesOnly;
    this.filter               = filter;
    this.searchResultListener = searchResultListener;

    if (sizeLimit < 0)
    {
      this.sizeLimit = 0;
    }
    else
    {
      this.sizeLimit = sizeLimit;
    }

    if (timeLimit < 0)
    {
      this.timeLimit = 0;
    }
    else
    {
      this.timeLimit = timeLimit;
    }

    if (attributes == null)
    {
      this.attributes = REQUEST_ATTRS_DEFAULT;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  public String getBaseDN()
  {
    return baseDN;
  }



  public void setBaseDN(final String baseDN)
  {
    ensureNotNull(baseDN);

    this.baseDN = baseDN;
  }


  public void setBaseDN(final DN baseDN)
  {
    ensureNotNull(baseDN);

    this.baseDN = baseDN.toString();
  }



  public SearchScope getScope()
  {
    return scope;
  }



  public void setScope(final SearchScope scope)
  {
    this.scope = scope;
  }



  public DereferencePolicy getDereferencePolicy()
  {
    return derefPolicy;
  }



  public void setDerefPolicy(final DereferencePolicy derefPolicy)
  {
    this.derefPolicy = derefPolicy;
  }

  public int getSizeLimit()
  {
    return sizeLimit;
  }


  public void setSizeLimit(final int sizeLimit)
  {
    if (sizeLimit < 0)
    {
      this.sizeLimit = 0;
    }
    else
    {
      this.sizeLimit = sizeLimit;
    }
  }



  public int getTimeLimitSeconds()
  {
    return timeLimit;
  }



  public void setTimeLimitSeconds(final int timeLimit)
  {
    if (timeLimit < 0)
    {
      this.timeLimit = 0;
    }
    else
    {
      this.timeLimit = timeLimit;
    }
  }


  public boolean typesOnly()
  {
    return typesOnly;
  }

  public void setTypesOnly(final boolean typesOnly)
  {
    this.typesOnly = typesOnly;
  }


  public Filter getFilter()
  {
    return filter;
  }


  public void setFilter(final String filter)
         throws LDAPException
  {
    ensureNotNull(filter);

    this.filter = Filter.create(filter);
  }




  public void setFilter(final Filter filter)
  {
    ensureNotNull(filter);

    this.filter = filter;
  }




  public String[] getAttributes()
  {
    return attributes;
  }

  public List<String> getAttributeList()
  {
    return Collections.unmodifiableList(Arrays.asList(attributes));
  }




  public void setAttributes(final String... attributes)
  {
    if (attributes == null)
    {
      this.attributes = REQUEST_ATTRS_DEFAULT;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  public void setAttributes(final List<String> attributes)
  {
    if (attributes == null)
    {
      this.attributes = REQUEST_ATTRS_DEFAULT;
    }
    else
    {
      this.attributes = new String[attributes.size()];
      for (int i=0; i < this.attributes.length; i++)
      {
        this.attributes[i] = attributes.get(i);
      }
    }
  }




  public SearchResultListener getSearchResultListener()
  {
    return searchResultListener;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST;
  }

  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST);
    writer.addOctetString(baseDN);
    writer.addEnumerated(scope.intValue());
    writer.addEnumerated(derefPolicy.intValue());
    writer.addInteger(sizeLimit);
    writer.addInteger(timeLimit);
    writer.addBoolean(typesOnly);
    filter.writeTo(writer);

    final ASN1BufferSequence attrSequence = writer.beginSequence();
    for (final String s : attributes)
    {
      writer.addOctetString(s);
    }
    attrSequence.end();
    requestSequence.end();
  }




  public ASN1Element encodeProtocolOp()
  {

    final ASN1Element[] attrElements = new ASN1Element[attributes.length];
    for (int i=0; i < attrElements.length; i++)
    {
      attrElements[i] = new ASN1OctetString(attributes[i]);
    }

    final ASN1Element[] protocolOpElements =
    {
      new ASN1OctetString(baseDN),
      new ASN1Enumerated(scope.intValue()),
      new ASN1Enumerated(derefPolicy.intValue()),
      new ASN1Integer(sizeLimit),
      new ASN1Integer(timeLimit),
      new ASN1Boolean(typesOnly),
      filter.encode(),
      new ASN1Sequence(attrElements)
    };

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
                            protocolOpElements);
  }



  @Override()
  protected SearchResult process(final LDAPConnection connection,
                                 final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection, depth,
           connection.getConnectionOptions().autoReconnect());
    }

    final long requestTime = System.nanoTime();
    processAsync(connection, null);

    try
    {
      final ArrayList<SearchResultEntry> entryList;
      final ArrayList<SearchResultReference> referenceList;
      if (searchResultListener == null)
      {
        entryList     = new ArrayList<SearchResultEntry>(5);
        referenceList = new ArrayList<SearchResultReference>(5);
      }
      else
      {
        entryList     = null;
        referenceList = null;
      }

      int numEntries    = 0;
      int numReferences = 0;
      ResultCode intermediateResultCode = ResultCode.SUCCESS;
      final long responseTimeout = getResponseTimeoutMillis(connection);
      while (true)
      {
        final LDAPResponse response;
        try
        {
          if (responseTimeout > 0)
          {
            response =
                 responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
          }
          else
          {
            response = responseQueue.take();
          }
        }
        catch (InterruptedException ie)
        {
          debugException(ie);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SEARCH_INTERRUPTED.get(connection.getHostPort()), ie);
        }

        if (response == null)
        {
          if (connection.getConnectionOptions().abandonOnTimeout())
          {
            connection.abandon(messageID);
          }

          final SearchResult searchResult =
               new SearchResult(messageID, ResultCode.TIMEOUT,
                    ERR_SEARCH_CLIENT_TIMEOUT.get(responseTimeout,
                         connection.getHostPort()),
                    null, null, entryList, referenceList, numEntries,
                    numReferences, null);
          throw new LDAPSearchException(searchResult);
        }

        if (response instanceof ConnectionClosedResponse)
        {
          final ConnectionClosedResponse ccr =
               (ConnectionClosedResponse) response;
          final String message = ccr.getMessage();
          if (message == null)
          {
            final SearchResult searchResult =
                 new SearchResult(messageID, ccr.getResultCode(),
                      ERR_CONN_CLOSED_WAITING_FOR_SEARCH_RESPONSE.get(
                           connection.getHostPort(), toString()),
                      null, null, entryList, referenceList, numEntries,
                      numReferences, null);
            throw new LDAPSearchException(searchResult);
          }
          else
          {

            final SearchResult searchResult =
                 new SearchResult(messageID, ccr.getResultCode(),
                      ERR_CONN_CLOSED_WAITING_FOR_SEARCH_RESPONSE_WITH_MESSAGE.
                           get(connection.getHostPort(), toString(), message),
                      null, null, entryList, referenceList, numEntries,
                      numReferences, null);
            throw new LDAPSearchException(searchResult);
          }
        }
        else if (response instanceof SearchResultEntry)
        {
          final SearchResultEntry searchEntry = (SearchResultEntry) response;
          numEntries++;
          if (searchResultListener == null)
          {
            entryList.add(searchEntry);
          }
          else
          {
            searchResultListener.searchEntryReturned(searchEntry);
          }
        }
        else if (response instanceof SearchResultReference)
        {
          final SearchResultReference searchReference =
               (SearchResultReference) response;
          if (followReferrals(connection))
          {
            final LDAPResult result = followSearchReference(messageID,
                 searchReference, connection, depth);
            if (! result.getResultCode().equals(ResultCode.SUCCESS))
            {
              numReferences++;
              if (searchResultListener == null)
              {
                referenceList.add(searchReference);
              }
              else
              {
                searchResultListener.searchReferenceReturned(searchReference);
              }

              if (intermediateResultCode.equals(ResultCode.SUCCESS))
              {
                intermediateResultCode = result.getResultCode();
              }
            }
            else if (result instanceof SearchResult)
            {
              final SearchResult searchResult = (SearchResult) result;
              numEntries += searchResult.getEntryCount();
              if (searchResultListener == null)
              {
                entryList.addAll(searchResult.getSearchEntries());
              }
            }
          }
          else
          {
            numReferences++;
            if (searchResultListener == null)
            {
              referenceList.add(searchReference);
            }
            else
            {
              searchResultListener.searchReferenceReturned(searchReference);
            }
          }
        }
        else
        {
          connection.getConnectionStatistics().incrementNumSearchResponses(
               numEntries, numReferences,
               (System.nanoTime() - requestTime));
          SearchResult result = (SearchResult) response;
          result.setCounts(numEntries, entryList, numReferences, referenceList);

          if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
              followReferrals(connection))
          {
            if (depth >=
                connection.getConnectionOptions().getReferralHopLimit())
            {
              return new SearchResult(messageID,
                                      ResultCode.REFERRAL_LIMIT_EXCEEDED,
                                      ERR_TOO_MANY_REFERRALS.get(),
                                      result.getMatchedDN(),
                                      result.getReferralURLs(), entryList,
                                      referenceList, numEntries,
                                      numReferences,
                                      result.getResponseControls());
            }

            result = followReferral(result, connection, depth);
          }

          if ((result.getResultCode().equals(ResultCode.SUCCESS)) &&
              (! intermediateResultCode.equals(ResultCode.SUCCESS)))
          {
            return new SearchResult(messageID, intermediateResultCode,
                                    result.getDiagnosticMessage(),
                                    result.getMatchedDN(),
                                    result.getReferralURLs(),
                                    entryList, referenceList, numEntries,
                                    numReferences,
                                    result.getResponseControls());
          }

          return result;
        }
      }
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }




  AsyncRequestID processAsync(final LDAPConnection connection,
                              final AsyncSearchResultListener resultListener)
                 throws LDAPException
  {

    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());

    final AsyncRequestID asyncRequestID;
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncSearchHelper helper = new AsyncSearchHelper(connection,
           messageID, resultListener, getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, helper);
      asyncRequestID = helper.getAsyncRequestID();

      final long timeout = getResponseTimeoutMillis(connection);
      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(helper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }


    try
    {
      debugLDAPRequest(this);
      connection.getConnectionStatistics().incrementNumSearchRequests();
      connection.sendMessage(message);
      return asyncRequestID;
    }
    catch (LDAPException le)
    {
      debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }



  private SearchResult processSync(final LDAPConnection connection,
                                   final int depth, final boolean allowRetry)
          throws LDAPException
  {
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    final long responseTimeout = getResponseTimeoutMillis(connection);
    try
    {
      connection.getConnectionInternals(true).getSocket().setSoTimeout(
           (int) responseTimeout);
    }
    catch (Exception e)
    {
      debugException(e);
    }


    final long requestTime = System.nanoTime();
    debugLDAPRequest(this);
    connection.getConnectionStatistics().incrementNumSearchRequests();
    try
    {
      connection.sendMessage(message);
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (allowRetry)
      {
        final SearchResult retryResult = reconnectAndRetry(connection, depth,
             le.getResultCode(), 0, 0);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      throw le;
    }

    final ArrayList<SearchResultEntry> entryList;
    final ArrayList<SearchResultReference> referenceList;
    if (searchResultListener == null)
    {
      entryList     = new ArrayList<SearchResultEntry>(5);
      referenceList = new ArrayList<SearchResultReference>(5);
    }
    else
    {
      entryList     = null;
      referenceList = null;
    }

    int numEntries    = 0;
    int numReferences = 0;
    ResultCode intermediateResultCode = ResultCode.SUCCESS;
    while (true)
    {
      final LDAPResponse response;
      try
      {
        response = connection.readResponse(messageID);
      }
      catch (final LDAPException le)
      {
        debugException(le);

        if ((le.getResultCode() == ResultCode.TIMEOUT) &&
            connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        if (allowRetry)
        {
          final SearchResult retryResult = reconnectAndRetry(connection, depth,
               le.getResultCode(), numEntries, numReferences);
          if (retryResult != null)
          {
            return retryResult;
          }
        }

        throw le;
      }

      if (response == null)
      {
        if (connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        throw new LDAPException(ResultCode.TIMEOUT,
             ERR_SEARCH_CLIENT_TIMEOUT.get(responseTimeout,
                  connection.getHostPort()));
      }
      else if (response instanceof ConnectionClosedResponse)
      {

        if (allowRetry)
        {
          final SearchResult retryResult = reconnectAndRetry(connection, depth,
               ResultCode.SERVER_DOWN, numEntries, numReferences);
          if (retryResult != null)
          {
            return retryResult;
          }
        }

        final ConnectionClosedResponse ccr =
             (ConnectionClosedResponse) response;
        final String msg = ccr.getMessage();
        if (msg == null)
        {
          final SearchResult searchResult =
               new SearchResult(messageID, ccr.getResultCode(),
                    ERR_CONN_CLOSED_WAITING_FOR_SEARCH_RESPONSE.get(
                         connection.getHostPort(), toString()),
                    null, null, entryList, referenceList, numEntries,
                    numReferences, null);
          throw new LDAPSearchException(searchResult);
        }
        else
        {
          final SearchResult searchResult =
               new SearchResult(messageID, ccr.getResultCode(),
                    ERR_CONN_CLOSED_WAITING_FOR_SEARCH_RESPONSE_WITH_MESSAGE.
                         get(connection.getHostPort(), toString(), msg),
                    null, null, entryList, referenceList, numEntries,
                    numReferences, null);
          throw new LDAPSearchException(searchResult);
        }
      }
      else if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else if (response instanceof SearchResultEntry)
      {
        final SearchResultEntry searchEntry = (SearchResultEntry) response;
        numEntries++;
        if (searchResultListener == null)
        {
          entryList.add(searchEntry);
        }
        else
        {
          searchResultListener.searchEntryReturned(searchEntry);
        }
      }
      else if (response instanceof SearchResultReference)
      {
        final SearchResultReference searchReference =
             (SearchResultReference) response;
        if (followReferrals(connection))
        {
          final LDAPResult result = followSearchReference(messageID,
               searchReference, connection, depth);
          if (! result.getResultCode().equals(ResultCode.SUCCESS))
          {

            numReferences++;
            if (searchResultListener == null)
            {
              referenceList.add(searchReference);
            }
            else
            {
              searchResultListener.searchReferenceReturned(searchReference);
            }

            if (intermediateResultCode.equals(ResultCode.SUCCESS))
            {
              intermediateResultCode = result.getResultCode();
            }
          }
          else if (result instanceof SearchResult)
          {
            final SearchResult searchResult = (SearchResult) result;
            numEntries += searchResult.getEntryCount();
            if (searchResultListener == null)
            {
              entryList.addAll(searchResult.getSearchEntries());
            }
          }
        }
        else
        {
          numReferences++;
          if (searchResultListener == null)
          {
            referenceList.add(searchReference);
          }
          else
          {
            searchResultListener.searchReferenceReturned(searchReference);
          }
        }
      }
      else
      {
        final SearchResult result = (SearchResult) response;
        if (allowRetry)
        {
          final SearchResult retryResult = reconnectAndRetry(connection,
               depth, result.getResultCode(), numEntries, numReferences);
          if (retryResult != null)
          {
            return retryResult;
          }
        }

        return handleResponse(connection, response, requestTime, depth,
                              numEntries, numReferences, entryList,
                              referenceList, intermediateResultCode);
      }
    }
  }


  private SearchResult reconnectAndRetry(final LDAPConnection connection,
                                         final int depth,
                                         final ResultCode resultCode,
                                         final int numEntries,
                                         final int numReferences)
  {
    try
    {

      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:

          connection.reconnect();
          if ((numEntries == 0) && (numReferences == 0))
          {
            return processSync(connection, depth, false);
          }
          break;
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    return null;
  }



  private SearchResult handleResponse(final LDAPConnection connection,
               final LDAPResponse response, final long requestTime,
               final int depth, final int numEntries, final int numReferences,
               final List<SearchResultEntry> entryList,
               final List<SearchResultReference> referenceList,
               final ResultCode intermediateResultCode)
          throws LDAPException
  {
    connection.getConnectionStatistics().incrementNumSearchResponses(
         numEntries, numReferences,
         (System.nanoTime() - requestTime));
    SearchResult result = (SearchResult) response;
    result.setCounts(numEntries, entryList, numReferences, referenceList);

    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >=
          connection.getConnectionOptions().getReferralHopLimit())
      {
        return new SearchResult(messageID,
                                ResultCode.REFERRAL_LIMIT_EXCEEDED,
                                ERR_TOO_MANY_REFERRALS.get(),
                                result.getMatchedDN(),
                                result.getReferralURLs(), entryList,
                                referenceList, numEntries,
                                numReferences,
                                result.getResponseControls());
      }

      result = followReferral(result, connection, depth);
    }

    if ((result.getResultCode().equals(ResultCode.SUCCESS)) &&
        (! intermediateResultCode.equals(ResultCode.SUCCESS)))
    {
      return new SearchResult(messageID, intermediateResultCode,
                              result.getDiagnosticMessage(),
                              result.getMatchedDN(),
                              result.getReferralURLs(),
                              entryList, referenceList, numEntries,
                              numReferences,
                              result.getResponseControls());
    }

    return result;
  }



  private LDAPResult followSearchReference(final int messageID,
                          final SearchResultReference searchReference,
                          final LDAPConnection connection, final int depth)
          throws LDAPException
  {
    for (final String urlString : searchReference.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {
          continue;
        }

        final String requestBaseDN;
        if (referralURL.baseDNProvided())
        {
          requestBaseDN = referralURL.getBaseDN().toString();
        }
        else
        {
          requestBaseDN = baseDN;
        }

        final SearchScope requestScope;
        if (referralURL.scopeProvided())
        {
          requestScope = referralURL.getScope();
        }
        else
        {
          requestScope = scope;
        }

        final Filter requestFilter;
        if (referralURL.filterProvided())
        {
          requestFilter = referralURL.getFilter();
        }
        else
        {
          requestFilter = filter;
        }


        final SearchRequest searchRequest =
             new SearchRequest(searchResultListener, getControls(),
                               requestBaseDN, requestScope, derefPolicy,
                               sizeLimit, timeLimit, typesOnly, requestFilter,
                               attributes);

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);

        try
        {
          return searchRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (LDAPException le)
      {
        debugException(le);

        if (le.getResultCode().equals(ResultCode.REFERRAL_LIMIT_EXCEEDED))
        {
          throw le;
        }
      }
    }

    return new SearchResult(messageID, ResultCode.REFERRAL, null, null,
                            searchReference.getReferralURLs(), 0, 0, null);
  }



  private SearchResult followReferral(final SearchResult referralResult,
                                      final LDAPConnection connection,
                                      final int depth)
          throws LDAPException
  {
    for (final String urlString : referralResult.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {

          continue;
        }

        final String requestBaseDN;
        if (referralURL.baseDNProvided())
        {
          requestBaseDN = referralURL.getBaseDN().toString();
        }
        else
        {
          requestBaseDN = baseDN;
        }

        final SearchScope requestScope;
        if (referralURL.scopeProvided())
        {
          requestScope = referralURL.getScope();
        }
        else
        {
          requestScope = scope;
        }

        final Filter requestFilter;
        if (referralURL.filterProvided())
        {
          requestFilter = referralURL.getFilter();
        }
        else
        {
          requestFilter = filter;
        }


        final SearchRequest searchRequest =
             new SearchRequest(searchResultListener, getControls(),
                               requestBaseDN, requestScope, derefPolicy,
                               sizeLimit, timeLimit, typesOnly, requestFilter,
                               attributes);

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return searchRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (LDAPException le)
      {
        debugException(le);

        if (le.getResultCode().equals(ResultCode.REFERRAL_LIMIT_EXCEEDED))
        {
          throw le;
        }
      }
    }

    return referralResult;
  }



  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(getExceptionMessage(e)), e);
    }
  }



  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }




  @Override()
  public OperationType getOperationType()
  {
    return OperationType.SEARCH;
  }




  public SearchRequest duplicate()
  {
    return duplicate(getControls());
  }




  public SearchRequest duplicate(final Control[] controls)
  {
    final SearchRequest r = new SearchRequest(searchResultListener, controls,
         baseDN, scope, derefPolicy, sizeLimit, timeLimit, typesOnly, filter,
         attributes);
    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchRequest(baseDN='");
    buffer.append(baseDN);
    buffer.append("', scope=");
    buffer.append(scope);
    buffer.append(", deref=");
    buffer.append(derefPolicy);
    buffer.append(", sizeLimit=");
    buffer.append(sizeLimit);
    buffer.append(", timeLimit=");
    buffer.append(timeLimit);
    buffer.append(", filter='");
    buffer.append(filter);
    buffer.append("', attrs={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(attributes[i]);
    }
    buffer.append('}');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
