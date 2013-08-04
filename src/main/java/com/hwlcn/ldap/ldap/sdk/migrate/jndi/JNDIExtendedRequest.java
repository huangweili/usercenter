package com.hwlcn.ldap.ldap.sdk.migrate.jndi;



import javax.naming.NamingException;

import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIExtendedRequest
       implements javax.naming.ldap.ExtendedRequest
{

  private static final long serialVersionUID = -8502230539753937274L;

  private final ExtendedRequest r;

  public JNDIExtendedRequest(final ExtendedRequest r)
  {
    this.r = r;
  }


  public JNDIExtendedRequest(final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    this.r = toSDKExtendedRequest(r);
  }


  public String getID()
  {
    return r.getOID();
  }

  public byte[] getEncodedValue()
  {
    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      return null;
    }
    else
    {
      return value.encode();
    }
  }


  public JNDIExtendedResponse createExtendedResponse(final String id,
                                   final byte[] berValue, final int offset,
                                   final int length)
         throws NamingException
  {
    return new JNDIExtendedResponse(id, berValue, offset, length);
  }


  public ExtendedRequest toSDKExtendedRequest()
  {
    return r;
  }

  public static ExtendedRequest toSDKExtendedRequest(
                                     final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    final ASN1OctetString value;
    final byte[] valueBytes = r.getEncodedValue();
    if (valueBytes == null)
    {
      value = null;
    }
    else
    {
      try
      {
        value = ASN1OctetString.decodeAsOctetString(valueBytes);
      }
      catch (ASN1Exception ae)
      {
        throw new NamingException(StaticUtils.getExceptionMessage(ae));
      }
    }

    return new ExtendedRequest(r.getID(), value);
  }

  @Override()
  public String toString()
  {
    return r.toString();
  }
}
