package com.hwlcn.ldap.ldap.sdk.migrate.jndi;



import javax.naming.NamingException;
import javax.naming.ldap.ExtendedResponse;

import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIExtendedResponse
       implements ExtendedResponse
{

  private static final long serialVersionUID = -9210853181740736844L;

  private final ExtendedResult r;

  public JNDIExtendedResponse(final ExtendedResult r)
  {
    this.r = r;
  }

  public JNDIExtendedResponse(final ExtendedResponse r)
         throws NamingException
  {
    this(toSDKExtendedResult(r));
  }



  JNDIExtendedResponse(final String id, final byte[] berValue, final int offset,
                       final int length)
       throws NamingException
  {
    final ASN1OctetString value;
    if (berValue == null)
    {
      value = null;
    }
    else
    {
      try
      {
        if ((offset == 0) && (length == berValue.length))
        {
          value = ASN1OctetString.decodeAsOctetString(berValue);
        }
        else
        {
          final byte[] valueBytes = new byte[length];
          System.arraycopy(berValue, offset, valueBytes, 0, length);
          value = ASN1OctetString.decodeAsOctetString(valueBytes);
        }
      }
      catch (ASN1Exception ae)
      {
        throw new NamingException(StaticUtils.getExceptionMessage(ae));
      }
    }

    r = new ExtendedResult(-1, ResultCode.SUCCESS, null, null, null, id, value,
                           null);
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

  public ExtendedResult toSDKExtendedResult()
  {
    return r;
  }


  public static ExtendedResult toSDKExtendedResult(final ExtendedResponse r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    final JNDIExtendedResponse response;
    final byte[] encodedValue = r.getEncodedValue();
    if (encodedValue == null)
    {
      response = new JNDIExtendedResponse(r.getID(), null, 0, 0);
    }
    else
    {
      response = new JNDIExtendedResponse(r.getID(), encodedValue, 0,
           encodedValue.length);
    }

    return response.toSDKExtendedResult();
  }


  @Override()
  public String toString()
  {
    return r.toString();
  }
}
