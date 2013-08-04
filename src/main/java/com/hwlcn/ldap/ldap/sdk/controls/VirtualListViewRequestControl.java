package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
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
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of the LDAP virtual list view (VLV)
 * request control as defined in draft-ietf-ldapext-ldapv3-vlv.  This control
 * may be used to retrieve arbitrary "pages" of entries from the complete set of
 * search results.  It is similar to the {@link com.hwlcn.ldap.ldap.sdk.controls.SimplePagedResultsControl}, with
 * the exception that the simple paged results control requires scrolling
 * through the results in sequential order, while the VLV control allows
 * starting and resuming at any arbitrary point in the result set.  The starting
 * point may be specified using either a positional offset, or based on the
 * first entry with a value that is greater than or equal to a specified value.
 * <BR><BR>
 * When the start of the result set is to be specified using an offset, then the
 * virtual list view request control should include the following elements:
 * <UL>
 *   <LI>{@code targetOffset} -- The position in the result set of the entry to
 *       target for the next page of results to return.  Note that the offset is
 *       one-based (so the first entry has offset 1, the second entry has offset
 *       2, etc.).</LI>
 *   <LI>{@code beforeCount} -- The number of entries before the entry specified
 *       as the target offset that should be retrieved.</LI>
 *   <LI>{@code afterCount} -- The number of entries after the entry specified
 *       as the target offset that should be retrieved.</LI>
 *   <LI>{@code contentCount} -- The estimated total number of entries that
 *       are in the total result set.  This should be zero for the first request
 *       in a VLV search sequence, but should be the value returned by the
 *       server in the corresponding response control for subsequent searches as
 *       part of the VLV sequence.</LI>
 *   <LI>{@code contextID} -- This is an optional cookie that may be used to
 *       help the server resume processing on a VLV search.  It should be absent
 *       from the initial request, but for subsequent requests should be the
 *       value returned in the previous VLV response control.</LI>
 * </UL>
 * When the start of the result set is to be specified using a search string,
 * then the virtual list view request control should include the following
 * elements:
 * <UL>
 *   <LI>{@code assertionValue} -- The value that specifies the start of the
 *       page of results to retrieve.  The target entry will be the first entry
 *       in which the value for the primary sort attribute is greater than or
 *       equal to this assertion value.</LI>
 *   <LI>{@code beforeCount} -- The number of entries before the entry specified
 *        by the assertion value that should be retrieved.</LI>
 *   <LI>{@code afterCount} -- The number of entries after the entry specified
 *       by the assertion value that should be retrieved.</LI>
 *   <LI>{@code contentCount} -- The estimated total number of entries that
 *       are in the total result set.  This should be zero for the first request
 *       in a VLV search sequence, but should be the value returned by the
 *       server in the corresponding response control for subsequent searches as
 *       part of the VLV sequence.</LI>
 *   <LI>{@code contextID} -- This is an optional cookie that may be used to
 *       help the server resume processing on a VLV search.  It should be absent
 *       from the initial request, but for subsequent requests should be the
 *       value returned in the previous VLV response control.</LI>
 * </UL>
 * Note that the virtual list view request control may only be included in a
 * search request if that search request also includes the
 * {@link com.hwlcn.ldap.ldap.sdk.controls.ServerSideSortRequestControl}.  This is necessary to ensure that a
 * consistent order is used for the resulting entries.
 * <BR><BR>
 * If the search is successful, then the search result done response may include
 * a {@link VirtualListViewResponseControl} to provide information about the
 * state of the virtual list view processing.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the virtual list view request
 * control to iterate through all users in the "Sales" department, retrieving
 * up to 10 entries at a time:
 * <PRE>
 *   ServerSideSortRequestControl sortRequest =
 *        new ServerSideSortRequestControl(new SortKey("sn"),
 *                                         new SortKey("givenName"));
 *   SearchRequest searchRequest =
 *        new SearchRequest("dc=example,dc=com", SearchScope.SUB, "(ou=Sales)");
 *
 *   int offset = 1;
 *   int contentCount = 0;
 *   ASN1OctetString contextID = null;
 *   do
 *   {
 *     VirtualListViewRequestControl vlvRequest =
 *          new VirtualListViewRequestControl(offset, 0, 9, contentCount,
 *                                            contextID);
 *     searchRequest.setControls(new Control[] { sortRequest, vlvRequest });
 *     SearchResult searchResult = connection.search();
 *
 *     // Do something with the entries that are returned.
 *
 *     contentCount = -1;
 *     VirtualListViewResponseControl c =
 *          VirtualListViewResponseControl.get(searchResult);
 *     if (c != null)
 *     {
 *       contentCount = c.getContentCount();
 *       contextID = c.getContextID();
 *     }
 *
 *     offset += 10;
 *   } while (offset &lt;= contentCount);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VirtualListViewRequestControl
       extends Control
{

  public static final String VIRTUAL_LIST_VIEW_REQUEST_OID =
       "2.16.840.1.113730.3.4.9";

  private static final byte TARGET_TYPE_OFFSET = (byte) 0xA0;

  private static final byte TARGET_TYPE_GREATER_OR_EQUAL = (byte) 0x81;

  private static final long serialVersionUID = 4348423177859960815L;

  private final ASN1OctetString assertionValue;

  private final ASN1OctetString contextID;

  private final int afterCount;

  private final int beforeCount;

  private final int contentCount;

  private final int targetOffset;



  public VirtualListViewRequestControl(final int targetOffset,
              final int beforeCount, final int afterCount,
              final int contentCount,  final ASN1OctetString contextID)
  {
    this(targetOffset, beforeCount, afterCount, contentCount, contextID, true);
  }



  public VirtualListViewRequestControl(final String assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
         contextID, true);
  }


  public VirtualListViewRequestControl(final byte[] assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
         contextID, true);
  }


  public VirtualListViewRequestControl(final ASN1OctetString assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID)
  {
    this(assertionValue, beforeCount, afterCount, contextID, true);
  }

  public VirtualListViewRequestControl(final int targetOffset,
              final int beforeCount, final int afterCount,
              final int contentCount,  final ASN1OctetString contextID,
              final boolean isCritical)
  {
    super(VIRTUAL_LIST_VIEW_REQUEST_OID, isCritical,
          encodeValue(targetOffset, beforeCount, afterCount, contentCount,
                      contextID));

    this.targetOffset = targetOffset;
    this.beforeCount  = beforeCount;
    this.afterCount   = afterCount;
    this.contentCount = contentCount;
    this.contextID    = contextID;

    assertionValue = null;
  }

  public VirtualListViewRequestControl(final String assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID, final boolean isCritical)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
                             contextID, isCritical);
  }


  public VirtualListViewRequestControl(final byte[] assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID, final boolean isCritical)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
                             contextID, isCritical);
  }



  public VirtualListViewRequestControl(final ASN1OctetString assertionValue,
              final int beforeCount, final int afterCount,
              final ASN1OctetString contextID, final boolean isCritical)
  {
    super(VIRTUAL_LIST_VIEW_REQUEST_OID, isCritical,
          encodeValue(assertionValue, beforeCount, afterCount, contextID));

    this.assertionValue = assertionValue;
    this.beforeCount    = beforeCount;
    this.afterCount     = afterCount;
    this.contextID      = contextID;

    targetOffset = -1;
    contentCount = -1;
  }


  public VirtualListViewRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();

      beforeCount = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      afterCount  = ASN1Integer.decodeAsInteger(elements[1]).intValue();

      switch (elements[2].getType())
      {
        case TARGET_TYPE_OFFSET:
          assertionValue = null;
          final ASN1Element[] offsetElements =
               ASN1Sequence.decodeAsSequence(elements[2]).elements();
          targetOffset =
               ASN1Integer.decodeAsInteger(offsetElements[0]).intValue();
          contentCount =
               ASN1Integer.decodeAsInteger(offsetElements[1]).intValue();
          break;

        case TARGET_TYPE_GREATER_OR_EQUAL:
          assertionValue = ASN1OctetString.decodeAsOctetString(elements[2]);
          targetOffset   = -1;
          contentCount   = -1;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_VLV_REQUEST_INVALID_ELEMENT_TYPE.get(
                                       toHex(elements[2].getType())));
      }

      if (elements.length == 4)
      {
        contextID = ASN1OctetString.decodeAsOctetString(elements[3]);
      }
      else
      {
        contextID = null;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }


  private static ASN1OctetString encodeValue(final int targetOffset,
                                             final int beforeCount,
                                             final int afterCount,
                                             final int contentCount,
                                             final ASN1OctetString contextID)
  {
    final ASN1Element[] targetElements =
    {
      new ASN1Integer(targetOffset),
      new ASN1Integer(contentCount)
    };

    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1Sequence(TARGET_TYPE_OFFSET, targetElements)
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1Sequence(TARGET_TYPE_OFFSET, targetElements),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }


  private static ASN1OctetString encodeValue(
                                      final ASN1OctetString assertionValue,
                                      final int beforeCount,
                                      final int afterCount,
                                      final ASN1OctetString contextID)
  {
    ensureNotNull(assertionValue);

    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1OctetString(TARGET_TYPE_GREATER_OR_EQUAL,
                            assertionValue.getValue())
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1OctetString(TARGET_TYPE_GREATER_OR_EQUAL,
                            assertionValue.getValue()),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }


  public int getTargetOffset()
  {
    return targetOffset;
  }


  public String getAssertionValueString()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.stringValue();
    }
  }


  public byte[] getAssertionValueBytes()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.getValue();
    }
  }


  public ASN1OctetString getAssertionValue()
  {
    return assertionValue;
  }

  public int getBeforeCount()
  {
    return beforeCount;
  }

  public int getAfterCount()
  {
    return afterCount;
  }


  public int getContentCount()
  {
    return contentCount;
  }


  public ASN1OctetString getContextID()
  {
    return contextID;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_VLV_REQUEST.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("VirtualListViewRequestControl(beforeCount=");
    buffer.append(beforeCount);
    buffer.append(", afterCount=");
    buffer.append(afterCount);

    if (assertionValue == null)
    {
      buffer.append(", targetOffset=");
      buffer.append(targetOffset);
      buffer.append(", contentCount=");
      buffer.append(contentCount);
    }
    else
    {
      buffer.append(", assertionValue='");
      buffer.append(assertionValue.stringValue());
      buffer.append('\'');
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
