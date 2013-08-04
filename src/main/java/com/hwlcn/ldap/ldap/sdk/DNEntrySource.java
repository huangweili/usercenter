package com.hwlcn.ldap.ldap.sdk;



import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an {@link com.hwlcn.ldap.ldap.sdk.EntrySource} that will retrieve entries
 * referenced by a provided set of DNs.  The connection will remain open after
 * all entries have been read.
 * <BR><BR>
 * It is not necessary to close this entry source when it is no longer needed,
 * although there is no cost or penalty in doing so.  Any exceptions thrown by
 * the {@link #nextEntry()} method will have the {@code mayContinueReading}
 * value set to {@code true}.
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving a static group
 * entry and using a {@code DNEntrySource} to iterate across the members of that
 * group:
 * <PRE>
 *   Entry groupEntry =
 *        connection.getEntry("cn=My Group,ou=Groups,dc=example,dc=com");
 *   String[] memberValues = groupEntry.getAttributeValues("member");
 *   if (memberValues != null)
 *   {
 *     DNEntrySource entrySource =
 *          new DNEntrySource(connection, memberValues, "cn");
 *     while (true)
 *     {
 *       Entry memberEntry = entrySource.nextEntry();
 *       if (memberEntry == null)
 *       {
 *         break;
 *       }
 *
 *       System.out.println("Retrieved member entry:  " +
 *            memberEntry.getAttributeValue("cn"));
 *     }
 *   }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DNEntrySource
       extends EntrySource
{

  private final Iterator<?> dnIterator;

  private final LDAPInterface connection;

  private final String[] attributes;



  public DNEntrySource(final LDAPInterface connection, final DN[] dns,
                       final String... attributes)
  {
    ensureNotNull(connection, dns);

    this.connection = connection;
    dnIterator = Arrays.asList(dns).iterator();

    if (attributes == null)
    {
      this.attributes = NO_STRINGS;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  public DNEntrySource(final LDAPInterface connection, final String[] dns,
                       final String... attributes)
  {
    this(connection, Arrays.asList(dns), attributes);
  }




  public DNEntrySource(final LDAPInterface connection,
                       final Collection<String> dns, final String... attributes)
  {
    ensureNotNull(connection, dns);

    this.connection = connection;
    dnIterator = dns.iterator();

    if (attributes == null)
    {
      this.attributes = NO_STRINGS;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  @Override()
  public Entry nextEntry()
         throws EntrySourceException
  {
    if (! dnIterator.hasNext())
    {
      return null;
    }

    final String dn = String.valueOf(dnIterator.next());
    try
    {
      final Entry e = connection.getEntry(dn, attributes);
      if (e == null)
      {
        throw new EntrySourceException(true,
             ERR_DN_ENTRY_SOURCE_NO_SUCH_ENTRY.get(dn),
             new LDAPException(ResultCode.NO_RESULTS_RETURNED));
      }
      else
      {
        return e;
      }
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new EntrySourceException(true,
           ERR_DN_ENTRY_SOURCE_ERR_RETRIEVING_ENTRY.get(dn,
                getExceptionMessage(le)),
           le);
    }
  }


  @Override()
  public void close()
  {
  }
}
