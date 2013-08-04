package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1OctetString;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ByteStringFactory
{

  private static final ASN1OctetString EMPTY_VALUE = new ASN1OctetString();



  private ByteStringFactory()
  {
  }




  public static ByteString create()
  {
    return EMPTY_VALUE;
  }



  public static ByteString create(final byte[] value)
  {
    return new ASN1OctetString(value);
  }



  public static ByteString create(final byte[] value, final int offset,
                                  final int length)
  {
    return new ASN1OctetString(value, offset, length);
  }




  public static ByteString create(final String value)
  {
    return new ASN1OctetString(value);
  }
}
