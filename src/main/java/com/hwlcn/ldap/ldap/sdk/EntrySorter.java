package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.controls.SortKey;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



/**
 * This class provides a mechanism for client-side entry sorting.  Sorting may
 * be based on attributes contained in the entry, and may also be based on the
 * hierarchical location of the entry in the DIT.  The sorting may be applied
 * to any collection of entries, including the entries included in a
 * {@link SearchResult} object.
 * <BR><BR>
 * This class provides a client-side alternative to the use of the
 * {@link com.hwlcn.ldap.ldap.sdk.controls.ServerSideSortRequestControl}.
 * Client-side sorting is most appropriate for small result sets, as it requires
 * all entries to be held in memory at the same time.  It is a good alternative
 * to server-side sorting when the overhead of sorting should be distributed
 * across client systems rather than on the server, and in cases in which the
 * target directory server does not support the use of the server-side sort
 * request control.
 * <BR><BR>
 * For best results, a {@link com.hwlcn.ldap.ldap.sdk.schema.Schema} object may be used to provide an
 * indication as to which matching rules should be used to perform the ordering.
 * If no {@code Schema} object is provided, then all ordering will be performed
 * using case-ignore string matching.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example may be used to obtain a sorted set of search result
 * entries, ordered first by sn and then by givenName, without consideration for
 * hierarchy:
 * <PRE>
 *   EntrySorter entrySorter = new EntrySorter(false,
 *        new SortKey("sn"), new SortKey("givenName"));
 *   SortedSet&lt;Entry&gt; sortedEntries =
 *        entrySorter.sort(searchResult.getSearchEntries())
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EntrySorter
       implements Comparator<Entry>, Serializable
{
  private static final long serialVersionUID = 7606107105238612142L;



  private final boolean sortByHierarchy;

  private final List<SortKey> sortKeys;

  private final Schema schema;

 public EntrySorter()
  {
    this(true, null, Collections.<SortKey>emptyList());
  }


  public EntrySorter(final boolean sortByHierarchy, final SortKey... sortKeys)
  {
    this(sortByHierarchy, null, Arrays.asList(sortKeys));
  }


  public EntrySorter(final boolean sortByHierarchy, final Schema schema,
                     final SortKey... sortKeys)
  {
    this(sortByHierarchy, schema, Arrays.asList(sortKeys));
  }


  public EntrySorter(final boolean sortByHierarchy,
                     final List<SortKey> sortKeys)
  {
    this(sortByHierarchy, null, sortKeys);
  }



  public EntrySorter(final boolean sortByHierarchy, final Schema schema,
                     final List<SortKey> sortKeys)
  {
    this.sortByHierarchy = sortByHierarchy;
    this.schema          = schema;

    if (sortKeys == null)
    {
      this.sortKeys = Collections.emptyList();
    }
    else
    {
      this.sortKeys =
           Collections.unmodifiableList(new ArrayList<SortKey>(sortKeys));
    }
  }



  public SortedSet<Entry> sort(final Collection<? extends Entry> entries)
  {
    final TreeSet<Entry> entrySet = new TreeSet<Entry>(this);
    entrySet.addAll(entries);
    return entrySet;
  }


  public int compare(final Entry e1, final Entry e2)
  {
    DN parsedDN1 = null;
    DN parsedDN2 = null;

    if (sortByHierarchy)
    {
      try
      {
        parsedDN1 = e1.getParsedDN();
        parsedDN2 = e2.getParsedDN();

        if (parsedDN1.isAncestorOf(parsedDN2, false))
        {
          return -1;
        }
        else if (parsedDN2.isAncestorOf(parsedDN1, false))
        {
          return 1;
        }
      }
      catch (LDAPException le)
      {
        debugException(le);
      }
    }

    for (final SortKey k : sortKeys)
    {
      final String attrName = k.getAttributeName();
      final Attribute a1 = e1.getAttribute(attrName);
      final Attribute a2 = e2.getAttribute(attrName);

      if ((a1 == null) || (! a1.hasValue()))
      {
        if ((a2 == null) || (! a2.hasValue()))
        {
          continue;
        }
        else
        {
          return 1;
        }
      }
      else
      {
        if ((a2 == null) || (! a2.hasValue()))
        {
          return -1;
        }
      }


      final MatchingRule matchingRule = MatchingRule.selectOrderingMatchingRule(
           attrName, k.getMatchingRuleID(), schema);
      if (k.reverseOrder())
      {
        ASN1OctetString v1 = null;
        for (final ASN1OctetString s : a1.getRawValues())
        {
          if (v1 == null)
          {
            v1 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v1) > 0)
              {
                v1 = s;
              }
            }
            catch (LDAPException le)
            {
              debugException(le);
            }
          }
        }

        ASN1OctetString v2 = null;
        for (final ASN1OctetString s : a2.getRawValues())
        {
          if (v2 == null)
          {
            v2 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v2) > 0)
              {
                v2 = s;
              }
            }
            catch (LDAPException le)
            {
              debugException(le);
            }
          }
        }

        try
        {
          final int value = matchingRule.compareValues(v2, v1);
          if (value != 0)
          {
            return value;
          }
        }
        catch (LDAPException le)
        {
          debugException(le);
        }
      }
      else
      {
        ASN1OctetString v1 = null;
        for (final ASN1OctetString s : a1.getRawValues())
        {
          if (v1 == null)
          {
            v1 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v1) < 0)
              {
                v1 = s;
              }
            }
            catch (LDAPException le)
            {
              debugException(le);
            }
          }
        }

        ASN1OctetString v2 = null;
        for (final ASN1OctetString s : a2.getRawValues())
        {
          if (v2 == null)
          {
            v2 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v2) < 0)
              {
                v2 = s;
              }
            }
            catch (LDAPException le)
            {
              debugException(le);
            }
          }
        }

        try
        {
          final int value = matchingRule.compareValues(v1, v2);
          if (value != 0)
          {
            return value;
          }
        }
        catch (LDAPException le)
        {
          debugException(le);
        }
      }
    }

try
    {
      if (parsedDN1 == null)
      {
        parsedDN1 = e1.getParsedDN();
      }

      if (parsedDN2 == null)
      {
        parsedDN2 = e2.getParsedDN();
      }

      return parsedDN1.compareTo(parsedDN2);
    }
    catch (LDAPException le)
    {
      debugException(le);
      final String lowerDN1 = toLowerCase(e1.getDN());
      final String lowerDN2 = toLowerCase(e2.getDN());
      return lowerDN1.compareTo(lowerDN2);
    }
  }



  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    if (sortByHierarchy)
    {
      hashCode++;
    }

    for (final SortKey k : sortKeys)
    {
      if (k.reverseOrder())
      {
        hashCode *= -31;
      }
      else
      {
        hashCode *= 31;
      }

      hashCode += toLowerCase(k.getAttributeName()).hashCode();
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

    if (! (o instanceof EntrySorter))
    {
      return false;
    }

    final EntrySorter s = (EntrySorter) o;
    if (sortByHierarchy != s.sortByHierarchy)
    {
      return false;
    }

    return sortKeys.equals(s.sortKeys);
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }




  public void toString(final StringBuilder buffer)
  {
    buffer.append("EntrySorter(sortByHierarchy=");
    buffer.append(sortByHierarchy);
    buffer.append(", sortKeys={");

    final Iterator<SortKey> iterator = sortKeys.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
