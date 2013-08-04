
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import static com.hwlcn.ldap.util.UtilityMessages.*;


@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class AggregateInputStream
       extends InputStream
{
  private volatile InputStream activeInputStream;

  private final Iterator<InputStream> streamIterator;

  public AggregateInputStream(final InputStream... inputStreams)
  {
    this(StaticUtils.toList(inputStreams));
  }

  public AggregateInputStream(
              final Collection<? extends InputStream> inputStreams)
  {
    Validator.ensureNotNull(inputStreams);

    final ArrayList<InputStream> streamList =
         new ArrayList<InputStream>(inputStreams);
    streamIterator = streamList.iterator();
    activeInputStream = null;
  }


  public AggregateInputStream(final File... files)
         throws IOException
  {
    Validator.ensureNotNull(files);

    final ArrayList<InputStream> streamList =
         new ArrayList<InputStream>(files.length);

    IOException ioException = null;
    for (final File f : files)
    {
      try
      {
        streamList.add(new FileInputStream(f));
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        ioException = ioe;
        break;
      }
    }

    if (ioException != null)
    {
      for (final InputStream s : streamList)
      {
        if (s != null)
        {
          try
          {
            s.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }

      throw ioException;
    }

    streamIterator = streamList.iterator();
    activeInputStream = null;
  }


  @Override()
  public int read()
         throws IOException
  {
    while (true)
    {
      if (activeInputStream == null)
      {
        if (streamIterator.hasNext())
        {
          activeInputStream = streamIterator.next();
          continue;
        }
        else
        {
          return -1;
        }
      }

      final int byteRead = activeInputStream.read();
      if (byteRead < 0)
      {
        activeInputStream.close();
        activeInputStream = null;
      }
      else
      {
        return byteRead;
      }
    }
  }



  @Override()
  public int read(final byte[] b)
         throws IOException
  {
    return read(b, 0, b.length);
  }




  @Override()
  public int read(final byte[] b, final int off, final int len)
         throws IOException
  {
    while (true)
    {
      if (activeInputStream == null)
      {
        if (streamIterator.hasNext())
        {
          activeInputStream = streamIterator.next();
          continue;
        }
        else
        {
          return -1;
        }
      }

      final int bytesRead = activeInputStream.read(b, off, len);
      if (bytesRead < 0)
      {
        activeInputStream.close();
        activeInputStream = null;
      }
      else
      {
        return bytesRead;
      }
    }
  }



  @Override()
  public long skip(final long n)
         throws IOException
  {
    if (activeInputStream == null)
    {
      if (streamIterator.hasNext())
      {
        activeInputStream = streamIterator.next();
        return activeInputStream.skip(n);
      }
      else
      {
        return 0L;
      }
    }
    else
    {
      return activeInputStream.skip(n);
    }
  }


  @Override()
  public int available()
         throws IOException
  {
    if (activeInputStream == null)
    {
      if (streamIterator.hasNext())
      {
        activeInputStream = streamIterator.next();
        return activeInputStream.available();
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return activeInputStream.available();
    }
  }


  @Override()
  public boolean markSupported()
  {
    return false;
  }


  @Override()
  public void mark(final int readLimit)
  {
  }



  @Override()
  public void reset()
         throws IOException
  {
    throw new IOException(ERR_AGGREGATE_INPUT_STREAM_MARK_NOT_SUPPORTED.get());
  }


  @Override()
  public void close()
         throws IOException
  {
    IOException firstException = null;

    if (activeInputStream != null)
    {
      try
      {
        activeInputStream.close();
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        firstException = ioe;
      }
      activeInputStream = null;
    }

    while (streamIterator.hasNext())
    {
      final InputStream s = streamIterator.next();
      try
      {
        s.close();
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        if (firstException == null)
        {
          firstException = ioe;
        }
      }
    }

    if (firstException != null)
    {
      throw firstException;
    }
  }
}
