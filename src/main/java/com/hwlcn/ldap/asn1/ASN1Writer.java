package com.hwlcn.ldap.asn1;



import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1Writer
{
  private static final ThreadLocal<ByteStringBuffer> buffers =
       new ThreadLocal<ByteStringBuffer>();

  private static final int MAX_BUFFER_LENGTH = 524288;



  private ASN1Writer()
  {

  }



  public static void writeElement(final ASN1Element element,
                                  final OutputStream outputStream)
         throws IOException
  {
    debugASN1Write(element);

    ByteStringBuffer buffer = buffers.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      buffers.set(buffer);
    }

    element.encodeTo(buffer);

    try
    {
      buffer.write(outputStream);
    }
    finally
    {
      if (buffer.capacity() > MAX_BUFFER_LENGTH)
      {
        buffer.setCapacity(MAX_BUFFER_LENGTH);
      }
      buffer.clear();
    }
  }



  public static void writeElement(final ASN1Element element,
                                  final ByteBuffer buffer)
         throws BufferOverflowException
  {
    debugASN1Write(element);

    ByteStringBuffer b = buffers.get();
    if (b == null)
    {
      b = new ByteStringBuffer();
      buffers.set(b);
    }

    element.encodeTo(b);

    try
    {
      if (buffer.remaining() < b.length())
      {
        throw new BufferOverflowException();
      }

      final int pos = buffer.position();
      buffer.put(b.getBackingArray(), 0, b.length());
      buffer.limit(buffer.position());
      buffer.position(pos);
    }
    finally
    {
      if (b.capacity() > MAX_BUFFER_LENGTH)
      {
        b.setCapacity(MAX_BUFFER_LENGTH);
      }
      b.clear();
    }
  }
}
