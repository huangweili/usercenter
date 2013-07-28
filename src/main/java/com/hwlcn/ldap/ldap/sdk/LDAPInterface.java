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



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  sizeLimit    The maximum number of entries that the server should
   *                      return for the search.  A value of zero indicates that
   *                      there should be no limit.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The filter to use to identify matching entries.  It
   *                      must not be {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  SearchResult search(final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final Filter filter, final String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The string representation of the filter to
   *                               use to identify matching entries.  It must
   *                               not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  SearchResult search(final SearchResultListener searchResultListener,
                      final String baseDN, final SearchScope scope,
                      final DereferencePolicy derefPolicy, final int sizeLimit,
                      final int timeLimit, final boolean typesOnly,
                      final String filter, final String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The filter to use to identify matching
   *                               entries.  It must not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
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
