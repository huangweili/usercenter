package com.hwlcn.ldap.asn1;



import java.io.Serializable;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1BufferSequence
       implements Serializable
{

  private static final long serialVersionUID = 7219098399193345629L;




  private final ASN1Buffer buffer;

  private final int valueStartPos;




  ASN1BufferSequence(final ASN1Buffer buffer)
  {
    this.buffer = buffer;

    valueStartPos = buffer.length();
  }


  public void end()
  {
    buffer.endSequenceOrSet(valueStartPos);
  }
}
