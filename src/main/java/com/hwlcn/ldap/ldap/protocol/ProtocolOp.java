package com.hwlcn.ldap.ldap.protocol;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ProtocolOp
       extends Serializable
{

  byte getProtocolOpType();



  ASN1Element encodeProtocolOp();



  void writeTo(final ASN1Buffer buffer);


  void toString(final StringBuilder buffer);
}
