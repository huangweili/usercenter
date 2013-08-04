package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP subentries request control
 * as defined in draft-ietf-ldup-subentry.  It may be included in a search
 * request to indicate that the entries with the {@code ldapSubentry} object
 * class should be included in the search results.
 * <BR><BR>
 * Entries containing the {@code ldapSubentry} object class are special in that
 * they are normally excluded from search results, unless the target entry is
 * requested with a base-level search.  They are used to store operational
 * information that controls how the server should behave rather than user data.
 * Because they do not hold user data, it is generally desirable to have them
 * excluded from search results, but for cases in which a client needs to
 * retrieve such an entry, then this subentries request control may be included
 * in the search request.
 * <BR><BR>
 * There is no corresponding response control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example illustrates the use of the subentries request control.
 * It attempts to retrieve all subentries defined below "dc=example,dc=com":
 * <PRE>
 *   SearchRequest searchRequest =
 *        new SearchRequest("dc=example,dc=com", SearchScope.SUB,
 *                          "(objectClass=ldapSubentry)");
 *   searchRequest.addControl(new SubentriesRequestControl());
 *   SearchResult searchResult = connection.search(searchRequest());
 *
 *   for (SearchResultEntry e : searchResult.getSearchEntries())
 *   {
 *     // Do something with the entry.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SubentriesRequestControl
       extends Control
{

  public static final String SUBENTRIES_REQUEST_OID =
       "1.3.6.1.4.1.7628.5.101.1";

  private static final long serialVersionUID = 4772130172594841481L;

  public SubentriesRequestControl()
  {
    this(false);
  }

  public SubentriesRequestControl(final boolean isCritical)
  {
    super(SUBENTRIES_REQUEST_OID, isCritical, null);
  }

  public SubentriesRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SUBENTRIES_HAS_VALUE.get());
    }
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SUBENTRIES_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SubentriesRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
