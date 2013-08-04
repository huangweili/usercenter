package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
/**
 * This class provides an implementation of the simple paged results control as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc2696.txt">RFC 2696</A>.  It
 * allows the client to iterate through a potentially large set of search
 * results in subsets of a specified number of entries (i.e., "pages").
 * <BR><BR>
 * The same control encoding is used for both the request control sent by
 * clients and the response control returned by the server.  It may contain
 * two elements:
 * <UL>
 *   <LI>Size -- In a request control, this provides the requested page size,
 *       which is the maximum number of entries that the server should return
 *       in the next iteration of the search.  In a response control, it is an
 *       estimate of the total number of entries that match the search
 *       criteria.</LI>
 *   <LI>Cookie -- A token which is used by the server to keep track of its
 *       position in the set of search results.  The first request sent by the
 *       client should not include a cookie, and the last response sent by the
 *       server should not include a cookie.  For all other intermediate search
 *       requests and responses,  the server will include a cookie value in its
 *       response that the client should include in its next request.</LI>
 * </UL>
 * When the client wishes to use the paged results control, the first search
 * request should include a version of the paged results request control that
 * was created with a requested page size but no cookie.  The corresponding
 * response from the server will include a version of the paged results control
 * that may include an estimate of the total number of matching entries, and
 * may also include a cookie.  The client should include this cookie in the
 * next request (with the same set of search criteria) to retrieve the next page
 * of results.  This process should continue until the response control returned
 * by the server does not include a cookie, which indicates that the end of the
 * result set has been reached.
 * <BR><BR>
 * Note that the simple paged results control is similar to the
 * {@link VirtualListViewRequestControl} in that both allow the client to
 * request that only a portion of the result set be returned at any one time.
 * However, there are significant differences between them, including:
 * <UL>
 *   <LI>In order to use the virtual list view request control, it is also
 *       necessary to use the {@link ServerSideSortRequestControl} to ensure
 *       that the entries are sorted.  This is not a requirement for the
 *       simple paged results control.</LI>
 *   <LI>The simple paged results control may only be used to iterate
 *       sequentially through the set of search results.  The virtual list view
 *       control can retrieve pages out of order, can retrieve overlapping
 *       pages, and can re-request pages that it had already retrieved.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the use of the simple paged results
 * control.  It will iterate through all users in the "Sales" department,
 * retrieving up to 10 entries at a time:
 * <PRE>
 *   SearchRequest searchRequest =
 *        new SearchRequest("dc=example,dc=com", SearchScope.SUB,"(ou=Sales)");
 *   ASN1OctetString cookie = null;
 *   do
 *   {
 *     searchRequest.setControls(
 *          new Control[] { new SimplePagedResultsControl(10, cookie) });
 *     SearchResult searchResult = connection.search(searchRequest);
 *
 *     // Do something with the entries that are returned.
 *
 *     cookie = null;
 *     SimplePagedResultControl c = SimplePagedResultControl.get(searchResult);
 *     if (c != null)
 *     {
 *       cookie = c.getCookie();
 *     }
 *   } while ((cookie != null) && (cookie.getValueLength() > 0));
 * </PRE>
 */


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SimplePagedResultsControl
       extends Control
       implements DecodeableControl
{

  public static final String PAGED_RESULTS_OID = "1.2.840.113556.1.4.319";


  private static final long serialVersionUID = 2186787148024999291L;




  private final ASN1OctetString cookie;


  private final int size;



  SimplePagedResultsControl()
  {
    size   = 0;
    cookie = new ASN1OctetString();
  }




  public SimplePagedResultsControl(final int pageSize)
  {
    super(PAGED_RESULTS_OID, false, encodeValue(pageSize, null));

    size   = pageSize;
    cookie = new ASN1OctetString();
  }




  public SimplePagedResultsControl(final int pageSize, final boolean isCritical)
  {
    super(PAGED_RESULTS_OID, isCritical, encodeValue(pageSize, null));

    size   = pageSize;
    cookie = new ASN1OctetString();
  }




  public SimplePagedResultsControl(final int pageSize,
                                   final ASN1OctetString cookie)
  {
    super(PAGED_RESULTS_OID, false, encodeValue(pageSize, cookie));

    size = pageSize;

    if (cookie == null)
    {
      this.cookie = new ASN1OctetString();
    }
    else
    {
      this.cookie = cookie;
    }
  }




  public SimplePagedResultsControl(final int pageSize,
                                   final ASN1OctetString cookie,
                                   final boolean isCritical)
  {
    super(PAGED_RESULTS_OID, isCritical, encodeValue(pageSize, cookie));

    size = pageSize;

    if (cookie == null)
    {
      this.cookie = new ASN1OctetString();
    }
    else
    {
      this.cookie = cookie;
    }
  }




  public SimplePagedResultsControl(final String oid, final boolean isCritical,
                                   final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      size = ASN1Integer.decodeAsInteger(valueElements[0]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_FIRST_NOT_INTEGER.get(ae), ae);
    }

    cookie = ASN1OctetString.decodeAsOctetString(valueElements[1]);
  }



  public SimplePagedResultsControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new SimplePagedResultsControl(oid, isCritical, value);
  }




  public static SimplePagedResultsControl get(final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PAGED_RESULTS_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof SimplePagedResultsControl)
    {
      return (SimplePagedResultsControl) c;
    }
    else
    {
      return new SimplePagedResultsControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  private static ASN1OctetString encodeValue(final int pageSize,
                                             final ASN1OctetString cookie)
  {
    final ASN1Element[] valueElements;
    if (cookie == null)
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Integer(pageSize),
        new ASN1OctetString()
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Integer(pageSize),
        cookie
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }


  public int getSize()
  {
    return size;
  }



  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  public boolean moreResultsToReturn()
  {
    return (cookie.getValue().length > 0);
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PAGED_RESULTS.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SimplePagedResultsControl(pageSize=");
    buffer.append(size);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
