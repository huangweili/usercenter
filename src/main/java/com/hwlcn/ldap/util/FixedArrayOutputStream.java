
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;

import static com.hwlcn.ldap.util.UtilityMessages.*;



@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class FixedArrayOutputStream
       extends OutputStream
       implements Serializable
{

  private static final long serialVersionUID = 4678108653480347534L;

  private final byte[] array;

  private final int initialPosition;

  private final int length;

  private final int maxPosition;

  private int pos;


  public FixedArrayOutputStream(final byte[] array)
  {
    this(array, 0, array.length);
  }



  public FixedArrayOutputStream(final byte[] array, final int pos,
                                   final int len)
  {
    this.array = array;
    this.pos   = pos;

    initialPosition = pos;
    maxPosition     = pos + len;
    length          = len;

    Validator.ensureTrue((pos >= 0),
         "The position must be greater than or equal to zero.");
    Validator.ensureTrue((len >= 0),
         "The length must be greater than or equal to zero.");
    Validator.ensureTrue((maxPosition <= array.length),
         "The sum of pos and len must not exceed the array length.");
  }



  public byte[] getBackingArray()
  {
    return array;
  }



  public int getInitialPosition()
  {
    return initialPosition;
  }


  public int getLength()
  {
    return length;
  }



  public int getBytesWritten()
  {
    return (pos - initialPosition);
  }

  @Override()
  public void close()
  {

  }


  @Override()
  public void flush()
  {
  }



  @Override()
  public void write(final int b)
         throws IOException
  {
    if (pos >= maxPosition)
    {
      throw new IOException(ERR_FIXED_ARRAY_OS_WRITE_BEYOND_END.get());
    }

    array[pos++] = (byte) b;
  }


  @Override()
  public void write(final byte[] b)
         throws IOException
  {
    write(b, 0, b.length);
  }



  @Override()
  public void write(final byte[] b, final int off, final int len)
         throws IOException
  {
    Validator.ensureTrue((off >= 0),
         "The provided offset must be greater than or equal to zero.");
    Validator.ensureTrue((len >= 0),
         "The provided length must be greater than or equal to zero.");
    Validator.ensureTrue(((off + len) <= b.length),
         "The sum of off and len must not exceed the array length.");

    if ((pos + len) > maxPosition)
    {
      throw new IOException(ERR_FIXED_ARRAY_OS_WRITE_BEYOND_END.get());
    }

    System.arraycopy(b, off, array, pos, len);
    pos += len;
  }
}
