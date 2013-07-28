package com.hwlcn.ldap.ldap.sdk;



import java.util.Collection;
import java.util.List;

import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPReadWriteConnectionPool
       implements LDAPInterface
{
  private final LDAPConnectionPool readPool;

  private final LDAPConnectionPool writePool;


  public LDAPReadWriteConnectionPool(final LDAPConnection readConnection,
              final int initialReadConnections, final int maxReadConnections,
              final LDAPConnection writeConnection,
              final int initialWriteConnections, final int maxWriteConnections)
         throws LDAPException
  {
    ensureNotNull(readConnection, writeConnection);
    ensureTrue(initialReadConnections >= 1,
               "LDAPReadWriteConnectionPool.initialReadConnections must be " +
                    "at least 1.");
    ensureTrue(maxReadConnections >= initialReadConnections,
               "LDAPReadWriteConnectionPool.initialReadConnections must not " +
                    "be greater than maxReadConnections.");
    ensureTrue(initialWriteConnections >= 1,
               "LDAPReadWriteConnectionPool.initialWriteConnections must be " +
                    "at least 1.");
    ensureTrue(maxWriteConnections >= initialWriteConnections,
               "LDAPReadWriteConnectionPool.initialWriteConnections must not " +
                    "be greater than maxWriteConnections.");

    readPool = new LDAPConnectionPool(readConnection, initialReadConnections,
                                      maxReadConnections);

    try
    {
      writePool = new LDAPConnectionPool(writeConnection,
           initialWriteConnections, maxWriteConnections);
    }
    catch (LDAPException le)
    {
      debugException(le);
      readPool.close();
      throw le;
    }
  }



  public LDAPReadWriteConnectionPool(final LDAPConnectionPool readPool,
                                     final LDAPConnectionPool writePool)
  {
    ensureNotNull(readPool, writePool);

    this.readPool  = readPool;
    this.writePool = writePool;
  }



  public void close()
  {
    readPool.close();
    writePool.close();
  }




  public boolean isClosed()
  {
    return readPool.isClosed() || writePool.isClosed();
  }



  public LDAPConnection getReadConnection()
         throws LDAPException
  {
    return readPool.getConnection();
  }



  public void releaseReadConnection(final LDAPConnection connection)
  {
    readPool.releaseConnection(connection);
  }



  public void releaseDefunctReadConnection(final LDAPConnection connection)
  {
    readPool.releaseDefunctConnection(connection);
  }


  public LDAPConnection getWriteConnection()
         throws LDAPException
  {
    return writePool.getConnection();
  }


  public void releaseWriteConnection(final LDAPConnection connection)
  {
    writePool.releaseConnection(connection);
  }


  public void releaseDefunctWriteConnection(final LDAPConnection connection)
  {
    writePool.releaseDefunctConnection(connection);
  }


  public LDAPConnectionPoolStatistics getReadPoolStatistics()
  {
    return readPool.getConnectionPoolStatistics();
  }


  public LDAPConnectionPoolStatistics getWritePoolStatistics()
  {
    return writePool.getConnectionPoolStatistics();
  }

  public LDAPConnectionPool getReadPool()
  {
    return readPool;
  }



  public LDAPConnectionPool getWritePool()
  {
    return writePool;
  }



  public RootDSE getRootDSE()
         throws LDAPException
  {
    return readPool.getRootDSE();
  }


  public Schema getSchema()
         throws LDAPException
  {
    return readPool.getSchema();
  }


  public Schema getSchema(final String entryDN)
         throws LDAPException
  {
    return readPool.getSchema(entryDN);
  }


  public SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    return readPool.getEntry(dn);
  }



  public SearchResultEntry getEntry(final String dn, final String... attributes)
         throws LDAPException
  {
    return readPool.getEntry(dn, attributes);
  }

  public LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    return writePool.add(dn, attributes);
  }


  public LDAPResult add(final String dn, final Collection<Attribute> attributes)
         throws LDAPException
  {
    return writePool.add(dn, attributes);
  }



  public LDAPResult add(final Entry entry)
         throws LDAPException
  {
    return writePool.add(entry);
  }



  public LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return writePool.add(ldifLines);
  }




  public LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    return writePool.add(addRequest);
  }



  public LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return writePool.add((AddRequest) addRequest);
  }



  public BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    return readPool.bind(bindDN, password);
  }



  public BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    return readPool.bind(bindRequest);
  }


  public CompareResult compare(final String dn, final String attributeName,
                               final String assertionValue)
         throws LDAPException
  {
    return readPool.compare(dn, attributeName, assertionValue);
  }


  public CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    return readPool.compare(compareRequest);
  }



  public CompareResult compare(final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return readPool.compare(compareRequest);
  }



  public LDAPResult delete(final String dn)
         throws LDAPException
  {
    return writePool.delete(dn);
  }


  public LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    return writePool.delete(deleteRequest);
  }



  public LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return writePool.delete(deleteRequest);
  }




  public LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    return writePool.modify(dn, mod);
  }




  public LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    return writePool.modify(dn, mods);
  }


  public LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    return writePool.modify(dn, mods);
  }



  public LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return writePool.modify(ldifModificationLines);
  }



  public LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    return writePool.modify(modifyRequest);
  }



  public LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return writePool.modify(modifyRequest);
  }



  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    return writePool.modifyDN(dn, newRDN, deleteOldRDN);
  }



  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN,
                             final String newSuperiorDN)
         throws LDAPException
  {
    return writePool.modifyDN(dn, newRDN, deleteOldRDN, newSuperiorDN);
  }



  public LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return writePool.modifyDN(modifyDNRequest);
  }


  public LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return writePool.modifyDN(modifyDNRequest);
  }



  public SearchResult search(final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, filter, attributes);
  }




  public SearchResult search(final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, filter, attributes);
  }



  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, filter,
                           attributes);
  }



  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, filter,
                           attributes);
  }


  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
                           typesOnly, filter, attributes);
  }



  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
                           typesOnly, filter, attributes);
  }



  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, derefPolicy,
                           sizeLimit, timeLimit, typesOnly, filter, attributes);
  }


  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, derefPolicy,
                           sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  public SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.search(searchRequest);
  }



  public SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.search(searchRequest);
  }



  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, filter, attributes);
  }


  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final Filter filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, filter, attributes);
  }


  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }


  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final Filter filter,
                                          final String... attributes)
       throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }


  public SearchResultEntry searchForEntry(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(searchRequest);
  }


  public SearchResultEntry searchForEntry(
                                final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(searchRequest);
  }



  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    close();
  }
}
