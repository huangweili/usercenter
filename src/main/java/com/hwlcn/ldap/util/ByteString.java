
package com.hwlcn.ldap.util;



import java.io.Serializable;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1OctetString;

@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ByteString
       extends Serializable
{

  byte[] getValue();


  String stringValue();

  void appendValueTo(final ByteStringBuffer buffer);

  ASN1OctetString toASN1OctetString();
}
