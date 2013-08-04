
package com.hwlcn.ldap.ldif;



import java.util.concurrent.atomic.AtomicBoolean;

import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.EntrySource;
import com.hwlcn.ldap.ldap.sdk.EntrySourceException;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an {@link com.hwlcn.ldap.ldap.sdk.EntrySource} that will read entries from an
 * LDIF file.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used for iterating
 * through all entries in an LDIF file using the entry source API:
 * <PRE>
 *   LDIFEntrySource entrySource =
 *        new LDIFEntrySource(new LDIFReader(pathToLDIFFile));
 *
 *   try
 *   {
 *     while (true)
 *     {
 *       try
 *       {
 *         Entry entry = entrySource.nextEntry();
 *         if (entry == null)
 *         {
 *           // There are no more entries to be read.
 *           break;
 *         }
 *         else
 *           {
 *           // Do something with the entry here.
 *         }
 *       }
 *       catch (EntrySourceException e)
 *       {
 *         // Some kind of problem was encountered (e.g., a malformed entry
 *         // found in the LDIF file, or an I/O error when trying to read).  See
 *         // if we can continue reading entries.
 *         if (! e.mayContinueReading())
 *         {
 *           break;
 *         }
 *       }
 *     }
 *   }
 *   finally
 *   {
 *     entrySource.close();
 *   }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFEntrySource
       extends EntrySource
{
  private final AtomicBoolean closed;

  private final LDIFReader ldifReader;

  public LDIFEntrySource(final LDIFReader ldifReader)
  {
    ensureNotNull(ldifReader);

    this.ldifReader = ldifReader;

    closed = new AtomicBoolean(false);
  }

  @Override()
  public Entry nextEntry()
         throws EntrySourceException
  {
    if (closed.get())
    {
      return null;
    }

    try
    {
      final Entry e = ldifReader.readEntry();
      if (e == null)
      {
        close();
      }

      return e;
    }
    catch (LDIFException le)
    {
      debugException(le);
      if (le.mayContinueReading())
      {
        throw new EntrySourceException(true, le);
      }
      else
      {
        close();
        throw new EntrySourceException(false, le);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      close();
      throw new EntrySourceException(false, e);
    }
  }


  @Override()
  public void close()
  {
    if (closed.compareAndSet(false, true))
    {
      try
      {
        ldifReader.close();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }
}
