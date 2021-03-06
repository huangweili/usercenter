package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of the server-side sort request
 * control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc2891.txt">RFC 2891</A>.  It may be
 * included in a search request to indicate that the server should sort the
 * results before returning them to the client.
 * <BR><BR>
 * The order in which the entries are to be sorted is specified by one or more
 * {@link com.hwlcn.ldap.ldap.sdk.controls.SortKey} values.  Each sort key includes an attribute name and a flag
 * that indicates whether to sort in ascending or descending order.  It may also
 * specify a custom matching rule that should be used to specify which logic
 * should be used to perform the sorting.
 * <BR><BR>
 * If the search is successful, then the search result done message may include
 * the {@link ServerSideSortResponseControl} to provide information about the
 * status of the sort processing.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the server-side sort controls
 * to retrieve all users in the Sales department, sorted by last name and then
 * by first name:
 * <PRE>
 *   SearchRequest searchRequest =
 *        new SearchRequest("dc=example,dc=com", SearchScope.SUB, "(ou=Sales)");
 *   searchRequest.addControl(new ServerSideSortRequestControl(
 *        new SortKey("sn"), new SortKey("givenName")));
 *   SearchResult searchResult = connection.search(searchRequest);
 * </PRE>
 * <BR><BR>
 * <H2>Client-Side Sorting</H2>
 * The UnboundID LDAP SDK for Java provides support for client-side sorting as
 * an alternative to server-side sorting.  Client-side sorting may be useful in
 * cases in which the target server does not support the use of the server-side
 * sort control, or when it is desirable to perform the sort processing on the
 * client systems rather than on the directory server systems.  See the
 * {@link com.hwlcn.ldap.ldap.sdk.EntrySorter} class for details on performing
 * client-side sorting in the LDAP SDK.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ServerSideSortRequestControl
       extends Control
{

  public static final String SERVER_SIDE_SORT_REQUEST_OID =
       "1.2.840.113556.1.4.473";


  private static final long serialVersionUID = -3021901578330574772L;

  private final SortKey[] sortKeys;


  public ServerSideSortRequestControl(final SortKey... sortKeys)
  {
    super(SERVER_SIDE_SORT_REQUEST_OID, false, encodeValue(sortKeys));

    this.sortKeys = sortKeys;
  }

  public ServerSideSortRequestControl(final boolean isCritical,
                                      final SortKey... sortKeys)
  {
    super(SERVER_SIDE_SORT_REQUEST_OID, isCritical, encodeValue(sortKeys));

    this.sortKeys = sortKeys;
  }


  public ServerSideSortRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      sortKeys = new SortKey[elements.length];
      for (int i=0; i < elements.length; i++)
      {
        sortKeys[i] = SortKey.decode(elements[i]);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }

  private static ASN1OctetString encodeValue(final SortKey[] sortKeys)
  {
    ensureNotNull(sortKeys);
    ensureTrue(sortKeys.length > 0,
               "ServerSideSortRequestControl.sortKeys must not be empty.");

    final ASN1Element[] valueElements = new ASN1Element[sortKeys.length];
    for (int i=0; i < sortKeys.length; i++)
    {
      valueElements[i] = sortKeys[i].encode();
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }

  public SortKey[] getSortKeys()
  {
    return sortKeys;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SORT_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ServerSideSortRequestControl(sortKeys={");

    for (int i=0; i < sortKeys.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      sortKeys[i].toString(buffer);
      buffer.append('\'');
    }

    buffer.append("})");
  }
}
