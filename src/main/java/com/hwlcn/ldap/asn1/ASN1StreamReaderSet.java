package com.hwlcn.ldap.asn1;



import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.asn1.ASN1Messages.*;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1StreamReaderSet
{

  private final ASN1StreamReader reader;

  private final byte type;


  private final int length;

  private final long endBytesRead;




  ASN1StreamReaderSet(final ASN1StreamReader reader, final byte type,
                      final int length)
  {
    this.reader = reader;
    this.type   = type;
    this.length = length;

    endBytesRead = reader.getTotalBytesRead() + length;
  }



  public byte getType()
  {
    return type;
  }




  public int getLength()
  {
    return length;
  }




  public boolean hasMoreElements()
         throws ASN1Exception
  {
    final long currentBytesRead = reader.getTotalBytesRead();
    if (currentBytesRead == endBytesRead)
    {
      return false;
    }
    else if (currentBytesRead < endBytesRead)
    {
      return true;
    }

    throw new ASN1Exception(ERR_STREAM_READER_SET_READ_PAST_END.get(
         length, endBytesRead, currentBytesRead));
  }
}
