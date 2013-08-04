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
 * This class provides an implementation of the matched values request control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc3876.txt">RFC 3876</A>.  It
 * should only be used with a search request, in which case it indicates that
 * only attribute values matching at least one of the provided
 * {@link com.hwlcn.ldap.ldap.sdk.controls.MatchedValuesFilter}s should be included in matching entries.  That
 * is, this control may be used to restrict the set of values included in the
 * entries that are returned.  This is particularly useful for multivalued
 * attributes with a large number of values when only a small number of values
 * are of interest to the client.
 * <BR><BR>
 * There are no corresponding response controls included in the search result
 * entry, search result reference, or search result done messages returned for
 * the associated search request.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the matched values request
 * control.  It will cause only values of the "{@code myIntValues}" attribute
 * to be returned in which those values are greater than or equal to five:
 * <PRE>
 *   SearchRequest searchRequest =
 *        new SearchRequest("uid=john.doe,ou=People,dc=example,dc=com",
 *                          SearchScope.BASE, "(objectClass=*)", "myIntValues");
 *   searchRequest.addControl(new MatchedValuesRequestControl(
 *        MatchedValuesFilter.createGreaterOrEqualFilter("myIntValues", "5"));
 *   SearchResult result = connection.search(searchRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchedValuesRequestControl
       extends Control
{

  public static final String MATCHED_VALUES_REQUEST_OID =
       "1.2.826.0.1.3344810.2.3";


  private static final long serialVersionUID = 6799850686547208774L;


  private final MatchedValuesFilter[] filters;




  public MatchedValuesRequestControl(final MatchedValuesFilter... filters)
  {
    this(false, filters);
  }

  public MatchedValuesRequestControl(final boolean isCritical,
                                     final MatchedValuesFilter... filters)
  {
    super(MATCHED_VALUES_REQUEST_OID, isCritical,  encodeValue(filters));

    this.filters = filters;
  }



  public MatchedValuesRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MV_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] filterElements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      filters = new MatchedValuesFilter[filterElements.length];
      for (int i=0; i < filterElements.length; i++)
      {
        filters[i] = MatchedValuesFilter.decode(filterElements[i]);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MV_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }


  private static ASN1OctetString encodeValue(
                                      final MatchedValuesFilter[] filters)
  {
    ensureNotNull(filters);
    ensureTrue(filters.length > 0,
               "MatchedValuesRequestControl.filters must not be empty.");

    final ASN1Element[] elements = new ASN1Element[filters.length];
    for (int i=0; i < filters.length; i++)
    {
      elements[i] = filters[i].encode();
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  public MatchedValuesFilter[] getFilters()
  {
    return filters;
  }



  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_MATCHED_VALUES_REQUEST.get();
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("MatchedValuesRequestControl(filters={");

    for (int i=0; i < filters.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      filters[i].toString(buffer);
      buffer.append('\'');
    }

    buffer.append("}, isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
