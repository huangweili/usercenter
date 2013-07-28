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
