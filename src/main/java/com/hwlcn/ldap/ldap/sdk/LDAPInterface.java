package com.hwlcn.ldap.ldap.sdk;



import java.util.Collection;
import java.util.List;

import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface LDAPInterface
{

  RootDSE getRootDSE()
       throws LDAPException;


  Schema getSchema()
       throws LDAPException;


  Schema getSchema(final String entryDN)
       throws LDAPException;




  SearchResultEntry getEntry(final String dn)
       throws LDAPException;



  SearchResultEntry getEntry(final String dn, final String... attributes)
       throws LDAPException;



  LDAPResult add(final String dn, final Attribute... attributes)
       throws LDAPException;


  LDAPResult add(final String dn, final Collection<Attribute> attributes)
       throws LDAPException;




  LDAPResult add(final Entry entry)
       throws LDAPException;




  LDAPResult add(final String... ldifLines)
       throws LDIFException, LDAPException;




  LDAPResult add(final AddRequest addRequest)
       throws LDAPException;




  LDAPResult add(final ReadOnlyAddRequest addRequest)
       throws LDAPException;




  CompareResult compare(final String dn, final String attributeName,
                        final String assertionValue)
       throws LDAPException;



  CompareResult compare(final CompareRequest compareRequest)
       throws LDAPException;



  CompareResult compare(final ReadOnlyCompareRequest compareRequest)
       throws LDAPException;



  LDAPResult delete(final String dn)
       throws LDAPException;



  LDAPResult delete(final DeleteRequest deleteRequest)
       throws LDAPException;


  LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
       throws LDAPException;



  LDAPResult modify(final String dn, final Modification mod)
       throws LDAPException;




  LDAPResult modify(final String dn, final Modification... mods)
       throws LDAPException;




  LDAPResult modify(final String dn, final List<Modification> mods)
       throws LDAPException;



  LDAPResult modify(final String... ldifModificationLines)
       throws LDIFException, LDAPException;




  LDAPResult modify(final ModifyRequest modifyRequest)
       throws LDAPException;



  LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
       throws LDAPException;




  LDAPResult modifyDN(final String dn, final String newRDN,
                      final boolean deleteOldRDN)
       throws LDAPException;



  LDAPResult modifyDN(final String dn, final String newRDN,
                      final boolean deleteOldRDN, final String newSuperiorDN)
       throws LDAPException;



  LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
       throws LDAPException;



  LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
       throws LDAPException;



  SearchResult search(final String baseDN, final SearchScope scope,
                      final String filter, final String... attributes)
       throws LDAPSearchException;




  SearchResult search(final String baseDN, final SearchScope scope,
                      final Filter filter, final String... attributes)
       throws LDAPSearchException;



  SearchResult search(final SearchResultListener searchResultListener,
                      final String baseDN, final SearchScope scope,
                      final String filter, final String... attributes)
       throws LDAPSearchException;



  SearchResult search(final SearchResultListener searchResultListener,
                      final String baseDN, final SearchScope scope,
                      final Filter filter, final String... attributes)
       throws LDAPSearchException;



  SearchResult search(final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final String filter, final String... attributes)
       throws LDAPSearchException;

  SearchResult search(final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final Filter filter, final String... attributes)
       throws LDAPSearchException;

  SearchResult search(final SearchResultListener searchResultListener,
                      final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final String filter, final String... attributes)
       throws LDAPSearchException;

  SearchResult search(final SearchResultListener searchResultListener,
                      final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final Filter filter, final String... attributes)
       throws LDAPSearchException;


  SearchResult search(final SearchRequest searchRequest)
       throws LDAPSearchException;




  SearchResult search(final ReadOnlySearchRequest searchRequest)
       throws LDAPSearchException;



  SearchResultEntry searchForEntry(final String baseDN, final SearchScope scope,
                                   final String filter,
                                   final String... attributes)
       throws LDAPSearchException;




  SearchResultEntry searchForEntry(final String baseDN, final SearchScope scope,
                                   final Filter filter,
                                   final String... attributes)
       throws LDAPSearchException;




  SearchResultEntry searchForEntry(final String baseDN, final SearchScope scope,
                                   final DereferencePolicy derefPolicy,
                                   final int timeLimit, final boolean typesOnly,
                                   final String filter,
                                   final String... attributes)
       throws LDAPSearchException;




  SearchResultEntry searchForEntry(final String baseDN, final SearchScope scope,
                                   final DereferencePolicy derefPolicy,
                                   final int timeLimit, final boolean typesOnly,
                                   final Filter filter,
                                   final String... attributes)
       throws LDAPSearchException;




  SearchResultEntry searchForEntry(final SearchRequest searchRequest)
       throws LDAPSearchException;




  SearchResultEntry searchForEntry(final ReadOnlySearchRequest searchRequest)
       throws LDAPSearchException;
}
