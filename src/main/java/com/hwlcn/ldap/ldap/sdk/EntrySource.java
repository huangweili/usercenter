package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be implemented by a class that provides
 * access to a sequence of entries, one entry at a time (e.g., entries read from
 * an LDIF file, or returned as part of an LDAP search).  It provides a
 * convenient way to operate on a set of entries without regard for the source
 * of those entries.  Implementations currently available include the
 * {@link LDAPEntrySource} class, which can be used to iterate across entries
 * returned from a directory server in response to a search request, and the
 * {@link com.hwlcn.ldap.ldif.LDIFEntrySource} class, which can be used to
 * iterate across entries in an LDIF file.
 * <BR><BR>
 * Note that the {@link #close} method MUST be called if the entry source is to
 * be discarded before guaranteeing that all entries have been read.  The
 * {@code close} method may be called after all entries have been read, but it
 * is not required.  All entry source implementations MUST ensure that all
 * resources are properly released if the caller has read through all entries,
 * or if an error occurs that prevents the caller from continuing to read
 * through the entries (i.e., if {@link #nextEntry} throws an
 * {@link EntrySourceException} and the
 * {@link EntrySourceException#mayContinueReading()} method returns
 * {@code false}).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used for iterating
 * across the entries provided by an entry source:
 * <PRE>
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
 *         {
 *           // Do something with the entry here.
 *         }
 *       }
 *       catch (EntrySourceException e)
 *       {
 *         // Some kind of problem was encountered (e.g., a malformed entry
 *         // found in an LDIF file, or a referral returned from a directory).
 *         // See if we can continue reading entries.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class EntrySource
{

  public abstract Entry nextEntry()
         throws EntrySourceException;


  public abstract void close();
}
