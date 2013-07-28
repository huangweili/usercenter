package com.hwlcn.ldap.asn1;



import java.io.Serializable;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;




@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1BufferSet
       implements Serializable
{

  private static final long serialVersionUID = 6686782295672518084L;



  private final ASN1Buffer buffer;


  private final int valueStartPos;




  ASN1BufferSet(final ASN1Buffer buffer)
  {
    this.buffer = buffer;

    valueStartPos = buffer.length();
  }


  public void end()
  {
    buffer.endSequenceOrSet(valueStartPos);
  }
}
