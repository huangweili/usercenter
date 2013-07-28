package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.logging.Level;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecordSet
      implements Serializable
{

  private static final String JNDI_DNS_CONTEXT_FACTORY =
       "com.sun.jndi.dns.DnsContextFactory";



  private static final String DNS_ATTR_SRV = "SRV";



  private static final String[] ATTRIBUTE_IDS = { DNS_ATTR_SRV };



  private static final long serialVersionUID = 7075112952759306499L;



  private final int totalRecords;

  private final List<SRVRecord> allRecords;

  private final List<SRVRecordPrioritySet> recordSets;
  private final long expirationTime;



  SRVRecordSet(final long expirationTime, final List<SRVRecord> records)
  {
    this.expirationTime = expirationTime;

    allRecords = Collections.unmodifiableList(records);
    totalRecords = records.size();

    final TreeMap<Long,List<SRVRecord>> m =
         new TreeMap<Long,List<SRVRecord>>();
    for (final SRVRecord r : records)
    {
      final Long priority = Long.valueOf(r.getPriority());
      List<SRVRecord> l = m.get(priority);
      if (l == null)
      {
        l = new ArrayList<SRVRecord>(records.size());
        m.put(priority, l);
      }

      l.add(r);
    }

    final ArrayList<SRVRecordPrioritySet> l =
         new ArrayList<SRVRecordPrioritySet>(m.size());
    for (final Map.Entry<Long,List<SRVRecord>> e : m.entrySet())
    {
      l.add(new SRVRecordPrioritySet(e.getKey(), e.getValue()));
    }

    recordSets = Collections.unmodifiableList(l);
  }



  long getExpirationTime()
  {
    return expirationTime;
  }



  boolean isExpired()
  {
    return (System.currentTimeMillis() >= expirationTime);
  }



  List<SRVRecord> getOrderedRecords()
  {
    final ArrayList<SRVRecord> l = new ArrayList<SRVRecord>(totalRecords);

    for (final SRVRecordPrioritySet s : recordSets)
    {
      l.addAll(s.getOrderedRecords());
    }

    return l;
  }


  static SRVRecordSet getRecordSet(final String name, final String providerURL,
                                   final long ttlMillis)
         throws LDAPException
  {
    final ArrayList<String> recordStrings = new ArrayList<String>(10);
    DirContext context = null;

    try
    {
      final Properties properties = new Properties();
      properties.setProperty(Context.INITIAL_CONTEXT_FACTORY,
           JNDI_DNS_CONTEXT_FACTORY);
      properties.setProperty(Context.PROVIDER_URL, providerURL);

      if (Debug.debugEnabled(DebugType.CONNECT))
      {
        Debug.debug(Level.INFO, DebugType.CONNECT,
             "Issuing JNDI query to retrieve DNS SRV record '" + name +
                  "' using provider URL '" + providerURL + "'.");
      }

      context = new InitialDirContext(properties);
      final Attributes recordAttributes =
           context.getAttributes(name, ATTRIBUTE_IDS);
      context.close();

      final Attribute srvAttr = recordAttributes.get(DNS_ATTR_SRV);
      if (srvAttr == null)
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SRV_RECORD_SET_NO_RECORDS.get(name));
      }

      final NamingEnumeration<?> values = srvAttr.getAll();
      while (values.hasMore())
      {
        final Object value = values.next();
        recordStrings.add(String.valueOf(value));
      }
      values.close();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_SET_ERROR_QUERYING_DNS.get(name,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (context != null)
      {
        try
        {
          context.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (recordStrings.isEmpty())
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_SET_NO_RECORDS.get(name));
    }

    final List<SRVRecord> recordList =
         new ArrayList<SRVRecord>(recordStrings.size());
    for (final String s : recordStrings)
    {
      final SRVRecord r = new SRVRecord(s);
      recordList.add(r);
      if (Debug.debugEnabled(DebugType.CONNECT))
      {
        Debug.debug(Level.INFO, DebugType.CONNECT,
             "Decoded DNS SRV record " + r.toString());
      }
    }

    return new SRVRecordSet(System.currentTimeMillis() + ttlMillis, recordList);
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  void toString(final StringBuilder buffer)
  {
    buffer.append("SRVRecordSet(records={");

    final Iterator<SRVRecord> iterator = allRecords.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().toString());
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
