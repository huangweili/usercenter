
package com.hwlcn.ldap.util;



import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1OctetString;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.UtilityMessages.*;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ByteStringBuffer
       implements Serializable, Appendable
{

  private static final int DEFAULT_INITIAL_CAPACITY = 20;



  private static final byte[] FALSE_VALUE_BYTES = StaticUtils.getBytes("false");

  private static final byte[] TRUE_VALUE_BYTES = StaticUtils.getBytes("true");

  private static final ThreadLocal<byte[]> TEMP_NUMBER_BUFFER =
       new ThreadLocal<byte[]>();


  private static final long serialVersionUID = 2899392249591230998L;

  private byte[] array;

  private int capacity;

  private int endPos;


  public ByteStringBuffer()
  {
    this(DEFAULT_INITIAL_CAPACITY);
  }


  public ByteStringBuffer(final int initialCapacity)
  {
    array    = new byte[initialCapacity];
    capacity = initialCapacity;
    endPos   = 0;
  }


  public ByteStringBuffer append(final boolean b)
  {
    if (b)
    {
      return append(TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return append(FALSE_VALUE_BYTES, 0, 5);
    }
  }


  public ByteStringBuffer append(final byte b)
  {
    ensureCapacity(endPos + 1);
    array[endPos++] = b;
    return this;
  }



  public ByteStringBuffer append(final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return append(b, 0, b.length);
  }

  public ByteStringBuffer append(final byte[] b, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > b.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }

    if (len > 0)
    {
      ensureCapacity(endPos + len);
      System.arraycopy(b, off, array, endPos, len);
      endPos += len;
    }

    return this;
  }

  public ByteStringBuffer append(final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
      throw e;
    }

    b.appendValueTo(this);
    return this;
  }



  public ByteStringBuffer append(final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return append(buffer.array, 0, buffer.endPos);
  }


  public ByteStringBuffer append(final char c)
  {
    final byte b = (byte) (c & 0x7F);
    if (b == c)
    {
      ensureCapacity(endPos + 1);
      array[endPos++] = b;
    }
    else
    {
      append(String.valueOf(c));
    }

    return this;
  }




  public ByteStringBuffer append(final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return append(c, 0, c.length);
  }



  public ByteStringBuffer append(final char[] c, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > c.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 c.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }

    if (len > 0)
    {
      ensureCapacity(endPos + len);

      int pos = off;
      for (int i=0; i < len; i++, pos++)
      {
        final byte b = (byte) (c[pos] & 0x7F);
        if (b == c[pos])
        {
          array[endPos++] = b;
        }
        else
        {
          append(String.valueOf(c, pos, (off + len - pos)));
          break;
        }
      }
    }

    return this;
  }


  public ByteStringBuffer append(final CharSequence s)
         throws NullPointerException
  {
    return append(s, 0, s.length());
  }



  public ByteStringBuffer append(final CharSequence s, final int start,
                                 final int end)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
      throw e;
    }

    final int length = end - start;
    ensureCapacity(endPos + length);
    for (int i=start; i < end; i++)
    {
      final char c = s.charAt(i);
      final byte b = (byte) (c & 0x7F);
      if (b == c)
      {
        array[endPos++] = b;
      }
      else
      {
        append(StaticUtils.getBytes(s.subSequence(i, length).toString()));
        break;
      }
    }

    return this;
  }



  public ByteStringBuffer append(final int i)
  {
    final int length = getBytes(i);
    return append(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  public ByteStringBuffer append(final long l)
  {
    final int length = getBytes(l);
    return append(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  public ByteStringBuffer insert(final int pos, final boolean b)
         throws  IndexOutOfBoundsException
  {
    if (b)
    {
      return insert(pos, TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return insert(pos, FALSE_VALUE_BYTES, 0, 5);
    }
  }


  public ByteStringBuffer insert(final int pos, final byte b)
         throws IndexOutOfBoundsException
  {
    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(b);
    }

    ensureCapacity(endPos + 1);
    System.arraycopy(array, pos, array, pos+1, (endPos-pos));
    array[pos] = b;
    endPos++;
    return this;
  }




  public ByteStringBuffer insert(final int pos, final byte[] b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return insert(pos, b, 0, b.length);
  }



  public ByteStringBuffer insert(final int pos, final byte[] b, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((pos < 0) || (pos > endPos) || (off < 0) || (len < 0) ||
        (off+len > b.length))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else if (pos > endPos)
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }
      else if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }
    else if (len == 0)
    {
      return this;
    }
    else if (pos == endPos)
    {
      return append(b, off, len);
    }

    ensureCapacity(endPos + len);
    System.arraycopy(array, pos, array, pos+len, (endPos-pos));
    System.arraycopy(b, off, array, pos, len);
    endPos += len;
    return this;
  }

  public ByteStringBuffer insert(final int pos, final ByteString b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return insert(pos, b.getValue());
  }



  public ByteStringBuffer insert(final int pos, final ByteStringBuffer buffer)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return insert(pos, buffer.array, 0, buffer.endPos);
  }




  public ByteStringBuffer insert(final int pos, final char c)
         throws IndexOutOfBoundsException
  {
    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(c);
    }

    final byte b = (byte) (c & 0x7F);
    if (b == c)
    {
      ensureCapacity(endPos + 1);
      System.arraycopy(array, pos, array, pos+1, (endPos-pos));
      array[pos] = b;
      endPos++;
    }
    else
    {
      insert(pos, String.valueOf(c));
    }

    return this;
  }



  public ByteStringBuffer insert(final int pos, final char[] c)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return insert(pos, new String(c, 0, c.length));
  }



  public ByteStringBuffer insert(final int pos, final char[] c, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    return insert(pos, new String(c, off, len));
  }



  public ByteStringBuffer insert(final int pos, final CharSequence s)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(s);
    }
    else
    {
      return insert(pos, StaticUtils.getBytes(s.toString()));
    }
  }


  public ByteStringBuffer insert(final int pos, final int i)
         throws IndexOutOfBoundsException
  {
    final int length = getBytes(i);
    return insert(pos, TEMP_NUMBER_BUFFER.get(), 0, length);
  }




  public ByteStringBuffer insert(final int pos, final long l)
         throws IndexOutOfBoundsException
  {
    final int length = getBytes(l);
    return insert(pos, TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  public ByteStringBuffer delete(final int len)
         throws IndexOutOfBoundsException
  {
    return delete(0, len);
  }



  public ByteStringBuffer delete(final int off, final int len)
         throws IndexOutOfBoundsException
  {
    if (off < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off));
    }
    else if (len < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len));
    }
    else if ((off + len) > endPos)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len, endPos));
    }
    else if (len == 0)
    {
      return this;
    }
    else if (off == 0)
    {
      if (len == endPos)
      {
        endPos = 0;
        return this;
      }
      else
      {
        final int newEndPos = endPos - len;
        System.arraycopy(array, len, array, 0, newEndPos);
        endPos = newEndPos;
        return this;
      }
    }
    else
    {
      if ((off + len) == endPos)
      {
        endPos = off;
        return this;
      }
      else
      {
        final int bytesToCopy = endPos - (off+len);
        System.arraycopy(array, (off+len), array, off, bytesToCopy);
        endPos -= len;
        return this;
      }
    }
  }



  public ByteStringBuffer set(final boolean b)
  {
    if (b)
    {
      return set(TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return set(FALSE_VALUE_BYTES, 0, 5);
    }
  }



  public ByteStringBuffer set(final byte b)
  {
    endPos = 0;
    return append(b);
  }




  public ByteStringBuffer set(final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(b, 0, b.length);
  }


  public ByteStringBuffer set(final byte[] b, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > b.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(b, off, len);
  }


  public ByteStringBuffer set(final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    b.appendValueTo(this);
    return this;
  }




  public ByteStringBuffer set(final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(buffer.array, 0, buffer.endPos);
  }


  public ByteStringBuffer set(final char c)
  {
    endPos = 0;
    return append(c);
  }



  public ByteStringBuffer set(final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(c, 0, c.length);
  }


  public ByteStringBuffer set(final char[] c, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > c.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 c.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(c, off, len);
  }




  public ByteStringBuffer set(final CharSequence s)
         throws NullPointerException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(s);
  }



  public ByteStringBuffer set(final int i)
  {
    final int length = getBytes(i);
    return set(TEMP_NUMBER_BUFFER.get(), 0, length);
  }


  public ByteStringBuffer set(final long l)
  {
    final int length = getBytes(l);
    return set(TEMP_NUMBER_BUFFER.get(), 0, length);
  }


  public ByteStringBuffer clear()
  {
    endPos = 0;
    return this;
  }



  public ByteStringBuffer clear(final boolean zero)
  {
    endPos = 0;

    if (zero)
    {
      Arrays.fill(array, (byte) 0x00);
    }

    return this;
  }



  public byte[] getBackingArray()
  {
    return array;
  }



  public boolean isEmpty()
  {
    return (endPos == 0);
  }



  public int length()
  {
    return endPos;
  }



  public void setLength(final int length)
         throws IndexOutOfBoundsException
  {
    if (length < 0)
    {
      final IndexOutOfBoundsException e = new IndexOutOfBoundsException(
           ERR_BS_BUFFER_LENGTH_NEGATIVE.get(length));
      debugCodingError(e);
      throw e;
    }

    if (length > endPos)
    {
      ensureCapacity(length);
      Arrays.fill(array, endPos, length, (byte) 0x00);
      endPos = length;
    }
    else
    {
      endPos = length;
    }
  }

  public int capacity()
  {
    return capacity;
  }




  public void ensureCapacity(final int minimumCapacity)
  {
    if (capacity < minimumCapacity)
    {
      final int newCapacity = Math.max(minimumCapacity, (2 * capacity) + 2);
      final byte[] newArray = new byte[newCapacity];
      System.arraycopy(array, 0, newArray, 0, capacity);
      array = newArray;
      capacity = newCapacity;
    }
  }


  public void setCapacity(final int capacity)
         throws IndexOutOfBoundsException
  {
    if (capacity < 0)
    {
      final IndexOutOfBoundsException e = new IndexOutOfBoundsException(
           ERR_BS_BUFFER_CAPACITY_NEGATIVE.get(capacity));
      debugCodingError(e);
      throw e;
    }

    if (this.capacity == capacity)
    {
      return;
    }
    else if (this.capacity < capacity)
    {
      final byte[] newArray = new byte[capacity];
      System.arraycopy(array, 0, newArray, 0, this.capacity);
      array = newArray;
      this.capacity = capacity;
    }
    else
    {
      final byte[] newArray = new byte[capacity];
      System.arraycopy(array, 0, newArray, 0, capacity);
      array = newArray;
      endPos = Math.min(endPos, capacity);
      this.capacity = capacity;
    }
  }



  public ByteStringBuffer trimToSize()
  {
    if (endPos != capacity)
    {
      final byte[] newArray = new byte[endPos];
      System.arraycopy(array, 0, newArray, 0, endPos);
      array = newArray;
      capacity = endPos;
    }

    return this;
  }


  public byte[] toByteArray()
  {
    final byte[] newArray = new byte[endPos];
    System.arraycopy(array, 0, newArray, 0, endPos);
    return newArray;
  }


  public ByteString toByteString()
  {
    return new ASN1OctetString(toByteArray());
  }


  public InputStream asInputStream()
  {
    return new ByteArrayInputStream(array, 0, endPos);
  }



  public void write(final OutputStream outputStream)
         throws IOException
  {
    outputStream.write(array, 0, endPos);
  }


  private static int getBytes(final long l)
  {
    byte[] b = TEMP_NUMBER_BUFFER.get();
    if (b == null)
    {
      b = new byte[20];
      TEMP_NUMBER_BUFFER.set(b);
    }

    if (l == Long.MIN_VALUE)
    {
      b[0]  = '-';
      b[1]  = '9';
      b[2]  = '2';
      b[3]  = '2';
      b[4]  = '3';
      b[5]  = '3';
      b[6]  = '7';
      b[7]  = '2';
      b[8]  = '0';
      b[9]  = '3';
      b[10] = '6';
      b[11] = '8';
      b[12] = '5';
      b[13] = '4';
      b[14] = '7';
      b[15] = '7';
      b[16] = '5';
      b[17] = '8';
      b[18] = '0';
      b[19] = '8';
      return 20;
    }
    else if (l == 0L)
    {
      b[0] = '0';
      return 1;
    }

    int pos = 0;
    long v = l;
    if (l < 0)
    {
      b[0] = '-';
      pos = 1;
      v = Math.abs(l);
    }

    long divisor;
    if (v <= 9L)
    {
      divisor = 1L;
    }
    else if (v <= 99L)
    {
      divisor = 10L;
    }
    else if (v <= 999L)
    {
      divisor = 100L;
    }
    else if (v <= 9999L)
    {
      divisor = 1000L;
    }
    else if (v <= 99999L)
    {
      divisor = 10000L;
    }
    else if (v <= 999999L)
    {
      divisor = 100000L;
    }
    else if (v <= 9999999L)
    {
      divisor = 1000000L;
    }
    else if (v <= 99999999L)
    {
      divisor = 10000000L;
    }
    else if (v <= 999999999L)
    {
      divisor = 100000000L;
    }
    else if (v <= 9999999999L)
    {
      divisor = 1000000000L;
    }
    else if (v <= 99999999999L)
    {
      divisor = 10000000000L;
    }
    else if (v <= 999999999999L)
    {
      divisor = 100000000000L;
    }
    else if (v <= 9999999999999L)
    {
      divisor = 1000000000000L;
    }
    else if (v <= 99999999999999L)
    {
      divisor = 10000000000000L;
    }
    else if (v <= 999999999999999L)
    {
      divisor = 100000000000000L;
    }
    else if (v <= 9999999999999999L)
    {
      divisor = 1000000000000000L;
    }
    else if (v <= 99999999999999999L)
    {
      divisor = 10000000000000000L;
    }
    else if (v <= 999999999999999999L)
    {
      divisor = 100000000000000000L;
    }
    else
    {
      divisor = 1000000000000000000L;
    }

    while (true)
    {
      final long digit = v / divisor;
      switch ((int) digit)
      {
        case 0:
          b[pos++] = '0';
          break;
        case 1:
          b[pos++] = '1';
          break;
        case 2:
          b[pos++] = '2';
          break;
        case 3:
          b[pos++] = '3';
          break;
        case 4:
          b[pos++] = '4';
          break;
        case 5:
          b[pos++] = '5';
          break;
        case 6:
          b[pos++] = '6';
          break;
        case 7:
          b[pos++] = '7';
          break;
        case 8:
          b[pos++] = '8';
          break;
        case 9:
          b[pos++] = '9';
          break;
      }

      if (divisor == 1L)
      {
        break;
      }
      else
      {
        v -= (divisor * digit);
        if (v == 0)
        {
          while (divisor > 1L)
          {
            b[pos++] = '0';
            divisor /= 10L;
          }

          break;
        }

        divisor /= 10L;
      }
    }

    return pos;
  }


  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    for (int i=0; i < endPos; i++)
    {
      hashCode += array[i];
    }

    return hashCode;
  }


  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof ByteStringBuffer))
    {
      return false;
    }

    final ByteStringBuffer b = (ByteStringBuffer) o;
    if (endPos != b.endPos)
    {
      return false;
    }

    for (int i=0; i < endPos; i++)
    {
      if (array[i] != b.array[i])
      {
        return false;
      }
    }

    return true;
  }


  public ByteStringBuffer duplicate()
  {
    final ByteStringBuffer newBuffer = new ByteStringBuffer(endPos);
    return newBuffer.append(this);
  }



  @Override()
  public String toString()
  {
    return StaticUtils.toUTF8String(array, 0, endPos);
  }
}
