
package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class AbstractConnectionPool
       implements LDAPInterface
{

  public abstract void close();


  public abstract void close(final boolean unbind, final int numThreads);

  public abstract boolean isClosed();


  public abstract LDAPConnection getConnection()
         throws LDAPException;



  public abstract void releaseConnection(final LDAPConnection connection);


  public abstract void releaseDefunctConnection(
                            final LDAPConnection connection);


  public final void releaseConnectionAfterException(
                         final LDAPConnection connection,
                         final LDAPException exception)
  {
    final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

    try
    {
      healthCheck.ensureConnectionValidAfterException(connection, exception);
      releaseConnection(connection);
    }
    catch (LDAPException le)
    {
      debugException(le);
      releaseDefunctConnection(connection);
    }
  }


  public abstract LDAPConnection replaceDefunctConnection(
                                      final LDAPConnection connection)
         throws LDAPException;


  private LDAPConnection replaceDefunctConnection(final Throwable t,
                              final LDAPConnection connection)
          throws LDAPException
  {
    try
    {
      return replaceDefunctConnection(connection);
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (t instanceof LDAPException)
      {
        throw (LDAPException) t;
      }
      else
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
      }
    }
  }


  public final boolean retryFailedOperationsDueToInvalidConnections()
  {
    return (! getOperationTypesToRetryDueToInvalidConnections().isEmpty());
  }


  public abstract Set<OperationType>
              getOperationTypesToRetryDueToInvalidConnections();


  public final void setRetryFailedOperationsDueToInvalidConnections(
              final boolean retryFailedOperationsDueToInvalidConnections)
  {
    if (retryFailedOperationsDueToInvalidConnections)
    {
      setRetryFailedOperationsDueToInvalidConnections(
           EnumSet.allOf(OperationType.class));
    }
    else
    {
      setRetryFailedOperationsDueToInvalidConnections(
           EnumSet.noneOf(OperationType.class));
    }
  }



  public abstract void setRetryFailedOperationsDueToInvalidConnections(
              final Set<OperationType> operationTypes);

  public abstract int getCurrentAvailableConnections();

  public abstract int getMaximumAvailableConnections();

  public abstract LDAPConnectionPoolStatistics getConnectionPoolStatistics();

  public abstract String getConnectionPoolName();

  public abstract void setConnectionPoolName(final String connectionPoolName);

  public abstract LDAPConnectionPoolHealthCheck getHealthCheck();

  public abstract long getHealthCheckIntervalMillis();

  public abstract void setHealthCheckIntervalMillis(
                            final long healthCheckInterval);

  protected abstract void doHealthCheck();

  public final RootDSE getRootDSE()
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final RootDSE rootDSE = conn.getRootDSE();
      releaseConnection(conn);
      return rootDSE;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final RootDSE rootDSE = newConn.getRootDSE();
        releaseConnection(newConn);
        return rootDSE;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }
      return null;
    }
  }



  public final Schema getSchema()
         throws LDAPException
  {
    return getSchema("");
  }


  public final Schema getSchema(final String entryDN)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final Schema schema = conn.getSchema(entryDN);
      releaseConnection(conn);
      return schema;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);


      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final Schema schema = newConn.getSchema(entryDN);
        releaseConnection(newConn);
        return schema;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }


  public final SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    return getEntry(dn, NO_STRINGS);
  }


  public final SearchResultEntry getEntry(final String dn,
                                          final String... attributes)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final SearchResultEntry entry = conn.getEntry(dn, attributes);
      releaseConnection(conn);
      return entry;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final SearchResultEntry entry = newConn.getEntry(dn, attributes);
        releaseConnection(newConn);
        return entry;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }

  public final LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }


  public final LDAPResult add(final String dn,
                              final Collection<Attribute> attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }


  public final LDAPResult add(final Entry entry)
         throws LDAPException
  {
    return add(new AddRequest(entry));
  }


  public final LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return add(new AddRequest(ldifLines));
  }


  public final LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(addRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.ADD, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.add(addRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }

  public final LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add((AddRequest) addRequest);
  }


  public final BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    return bind(new SimpleBindRequest(bindDN, password));
  }


  public final BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.BIND, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final BindResult result = newConn.bind(bindRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }



  public final CompareResult compare(final String dn,
                                     final String attributeName,
                                     final String assertionValue)
         throws LDAPException
  {
    return compare(new CompareRequest(dn, attributeName, assertionValue));
  }



  public final CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final CompareResult result = conn.compare(compareRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.COMPARE, conn);
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final CompareResult result = newConn.compare(compareRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }


  public final CompareResult compare(
                                  final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return compare((CompareRequest) compareRequest);
  }

  public final LDAPResult delete(final String dn)
         throws LDAPException
  {
    return delete(new DeleteRequest(dn));
  }

  public final LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.delete(deleteRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.DELETE, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.delete(deleteRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }


  public final LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return delete((DeleteRequest) deleteRequest);
  }


  public final ExtendedResult processExtendedOperation(final String requestOID)
         throws LDAPException
  {
    return processExtendedOperation(new ExtendedRequest(requestOID));
  }


  public final ExtendedResult processExtendedOperation(final String requestOID,
                                   final ASN1OctetString requestValue)
         throws LDAPException
  {
    return processExtendedOperation(new ExtendedRequest(requestOID,
         requestValue));
  }


  public final ExtendedResult processExtendedOperation(
                                   final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    if (extendedRequest.getOID().equals(
         StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
                              ERR_POOL_STARTTLS_NOT_ALLOWED.get());
    }

    final LDAPConnection conn = getConnection();

    try
    {
      final ExtendedResult result =
           conn.processExtendedOperation(extendedRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.EXTENDED, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final ExtendedResult result =
             newConn.processExtendedOperation(extendedRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }

  public final LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mod));
  }


  public final LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }


  public final LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }



  public final LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return modify(new ModifyRequest(ldifModificationLines));
  }


  public final LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(modifyRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.MODIFY, conn);
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.modify(modifyRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      return null;
    }
  }


  public final LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return modify((ModifyRequest) modifyRequest);
  }

  public final LDAPResult modifyDN(final String dn, final String newRDN,
                                   final boolean deleteOldRDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN));
  }


  public final LDAPResult modifyDN(final String dn, final String newRDN,
                                   final boolean deleteOldRDN,
                                   final String newSuperiorDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN,
         newSuperiorDN));
  }


  public final LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modifyDN(modifyDNRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.MODIFY_DN, conn);

      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.modifyDN(modifyDNRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }
      return null;
    }
  }

  public final LDAPResult modifyDN(
                               final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN((ModifyDNRequest) modifyDNRequest);
  }


  public final SearchResult search(final String baseDN, final SearchScope scope,
                                   final String filter,
                                   final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, parseFilter(filter),
         attributes));
  }


  public final SearchResult search(final String baseDN, final SearchScope scope,
                                   final Filter filter,
                                   final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, filter, attributes));
  }


  public final SearchResult
       search(final SearchResultListener searchResultListener,
              final String baseDN, final SearchScope scope, final String filter,
              final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         parseFilter(filter), attributes));
  }


  public final SearchResult
       search(final SearchResultListener searchResultListener,
              final String baseDN, final SearchScope scope, final Filter filter,
              final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         filter, attributes));
  }

  public final SearchResult search(final String baseDN, final SearchScope scope,
                                   final DereferencePolicy derefPolicy,
                                   final int sizeLimit, final int timeLimit,
                                   final boolean typesOnly, final String filter,
                                   final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, parseFilter(filter), attributes));
  }

  public final SearchResult search(final String baseDN, final SearchScope scope,
                                   final DereferencePolicy derefPolicy,
                                   final int sizeLimit, final int timeLimit,
                                   final boolean typesOnly, final Filter filter,
                                   final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, filter, attributes));
  }
  public final SearchResult
       search(final SearchResultListener searchResultListener,
              final String baseDN, final SearchScope scope,
              final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly, final String filter,
              final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, parseFilter(filter),
         attributes));
  }

  public final SearchResult
        search(final SearchResultListener searchResultListener,
               final String baseDN, final SearchScope scope,
               final DereferencePolicy derefPolicy, final int sizeLimit,
               final int timeLimit, final boolean typesOnly,
               final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, filter, attributes));
  }
  public final SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(searchRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchExceptionIfShouldNotRetry(t, conn);

      final LDAPConnection newConn;
      try
      {
        newConn = replaceDefunctConnection(t, conn);
      }
      catch (final LDAPException le)
      {
        debugException(le);
        throw new LDAPSearchException(le);
      }

      try
      {
        final SearchResult result = newConn.search(searchRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPSearchException(t2, newConn);
      }

      return null;
    }
  }

  public final SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search((SearchRequest) searchRequest);
  }

  public final SearchResultEntry searchForEntry(final String baseDN,
                                                final SearchScope scope,
                                                final String filter,
                                                final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, parseFilter(filter),
         attributes));
  }
  public final SearchResultEntry searchForEntry(final String baseDN,
                                                final SearchScope scope,
                                                final Filter filter,
                                                final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, filter, attributes));
  }

  public final SearchResultEntry
       searchForEntry(final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int timeLimit,
                      final boolean typesOnly, final String filter,
                      final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, parseFilter(filter), attributes));
  }

  public final SearchResultEntry
       searchForEntry(final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int timeLimit,
                      final boolean typesOnly, final Filter filter,
                      final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, filter, attributes));
  }
  public final SearchResultEntry searchForEntry(
                                      final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResultEntry entry = conn.searchForEntry(searchRequest);
      releaseConnection(conn);
      return entry;
    }
    catch (Throwable t)
    {
      throwLDAPSearchExceptionIfShouldNotRetry(t, conn);

      final LDAPConnection newConn;
      try
      {
        newConn = replaceDefunctConnection(t, conn);
      }
      catch (final LDAPException le)
      {
        debugException(le);
        throw new LDAPSearchException(le);
      }

      try
      {
        final SearchResultEntry entry = newConn.searchForEntry(searchRequest);
        releaseConnection(newConn);
        return entry;
      }
      catch (final Throwable t2)
      {
        throwLDAPSearchException(t2, newConn);
      }

      return null;
    }
  }


  public final SearchResultEntry searchForEntry(
                                      final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return searchForEntry((SearchRequest) searchRequest);
  }

  private static Filter parseFilter(final String filterString)
          throws LDAPSearchException
  {
    try
    {
      return Filter.create(filterString);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }

  public final List<LDAPResult> processRequests(
                                     final List<LDAPRequest> requests,
                                     final boolean continueOnError)
         throws LDAPException
  {
    ensureNotNull(requests);
    ensureFalse(requests.isEmpty(),
         "LDAPConnectionPool.processRequests.requests must not be empty.");

    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    final ArrayList<LDAPResult> results =
         new ArrayList<LDAPResult>(requests.size());
    boolean isDefunct = false;

    try
    {
requestLoop:
      for (final LDAPRequest request : requests)
      {
        try
        {
          final LDAPResult result = request.process(conn, 1);
          results.add(result);
          switch (result.getResultCode().intValue())
          {
            case ResultCode.SUCCESS_INT_VALUE:
            case ResultCode.COMPARE_FALSE_INT_VALUE:
            case ResultCode.COMPARE_TRUE_INT_VALUE:
            case ResultCode.NO_OPERATION_INT_VALUE:
              break;

            default:
              if (! ResultCode.isConnectionUsable(result.getResultCode()))
              {
                isDefunct = true;
              }

              if (! continueOnError)
              {
                break requestLoop;
              }
              break;
          }
        }
        catch (LDAPException le)
        {
          debugException(le);
          results.add(new LDAPResult(request.getLastMessageID(),
                                     le.getResultCode(), le.getMessage(),
                                     le.getMatchedDN(), le.getReferralURLs(),
                                     le.getResponseControls()));

          if (! ResultCode.isConnectionUsable(le.getResultCode()))
          {
            isDefunct = true;
          }

          if (! continueOnError)
          {
            break;
          }
        }
      }
    }
    finally
    {
      if (isDefunct)
      {
        releaseDefunctConnection(conn);
      }
      else
      {
        releaseConnection(conn);
      }
    }

    return results;
  }


  private void throwLDAPExceptionIfShouldNotRetry(final Throwable t,
                                                  final OperationType o,
                                                  final LDAPConnection conn)
          throws LDAPException
  {
    if ((t instanceof LDAPException) &&
        getOperationTypesToRetryDueToInvalidConnections().contains(o))
    {
      final LDAPException le = (LDAPException) t;
      final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

      try
      {
        healthCheck.ensureConnectionValidAfterException(conn, le);
      }
      catch (final Exception e)
      {

        debugException(e);
        return;
      }
    }

    throwLDAPException(t, conn);
  }


  private void throwLDAPSearchExceptionIfShouldNotRetry(final Throwable t,
                    final LDAPConnection conn)
          throws LDAPSearchException
  {
    if ((t instanceof LDAPException) &&
        getOperationTypesToRetryDueToInvalidConnections().contains(
             OperationType.SEARCH))
    {
      final LDAPException le = (LDAPException) t;
      final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

      try
      {
        healthCheck.ensureConnectionValidAfterException(conn, le);
      }
      catch (final Exception e)
      {
        debugException(e);
        return;
      }
    }

    throwLDAPSearchException(t, conn);
  }


  void throwLDAPException(final Throwable t, final LDAPConnection conn)
       throws LDAPException
  {
    debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPException le = (LDAPException) t;
      releaseConnectionAfterException(conn, le);
      throw le;
    }
    else
    {
      releaseDefunctConnection(conn);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
    }
  }


  void throwLDAPSearchException(final Throwable t, final LDAPConnection conn)
       throws LDAPSearchException
  {
    debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPSearchException lse;
      if (t instanceof LDAPSearchException)
      {
        lse = (LDAPSearchException) t;
      }
      else
      {
        lse = new LDAPSearchException((LDAPException) t);
      }

      releaseConnectionAfterException(conn, lse);
      throw lse;
    }
    else
    {
      releaseDefunctConnection(conn);
      throw new LDAPSearchException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
    }
  }


  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public abstract void toString(final StringBuilder buffer);
}
