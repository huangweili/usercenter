package com.hwlcn.ldap.ldap.sdk;



import javax.net.SocketFactory;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNSSRVRecordServerSet
       extends ServerSet
{
  private static final String DEFAULT_RECORD_NAME = "_ldap._tcp";



  private static final long DEFAULT_TTL_MILLIS = 60L * 60L * 1000L;



  private static final String DEFAULT_DNS_PROVIDER_URL = "dns:";

  private final LDAPConnectionOptions connectionOptions;

  private final long ttlMillis;

  private final SocketFactory socketFactory;

  private volatile SRVRecordSet recordSet;

  private final String recordName;

  private final String providerURL;




  public DNSSRVRecordServerSet(final String recordName)
  {
    this(recordName, null, DEFAULT_TTL_MILLIS, null, null);
  }



  public DNSSRVRecordServerSet(final String recordName,
                               final String providerURL, final long ttlMillis,
                               final SocketFactory socketFactory,
                               final LDAPConnectionOptions connectionOptions)
  {
    this.socketFactory     = socketFactory;
    this.connectionOptions = connectionOptions;

    recordSet = null;

    if (recordName == null)
    {
      this.recordName = DEFAULT_RECORD_NAME;
    }
    else
    {
      this.recordName = recordName;
    }

    if (providerURL == null)
    {
      this.providerURL = DEFAULT_DNS_PROVIDER_URL;
    }
    else
    {
      this.providerURL = providerURL;
    }

    if (ttlMillis <= 0L)
    {
      this.ttlMillis = DEFAULT_TTL_MILLIS;
    }
    else
    {
      this.ttlMillis = ttlMillis;
    }
  }



  public String getRecordName()
  {
    return recordName;
  }



  public String getProviderURL()
  {
    return providerURL;
  }




  public long getTTLMillis()
  {
    return ttlMillis;
  }



  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  @Override()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
  }




  @Override()
  public LDAPConnection getConnection(
                             final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    if ((recordSet == null) || recordSet.isExpired())
    {
      try
      {
        recordSet = SRVRecordSet.getRecordSet(recordName, providerURL,
             ttlMillis);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        if (recordSet == null)
        {
          throw le;
        }
      }
    }

    LDAPException firstException = null;
    for (final SRVRecord r : recordSet.getOrderedRecords())
    {
      final LDAPConnection conn;
      try
      {
        conn = new LDAPConnection(socketFactory, connectionOptions,
             r.getAddress(), r.getPort());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        if (firstException == null)
        {
          firstException = le;
        }

        continue;
      }

      if (healthCheck != null)
      {
        try
        {
          healthCheck.ensureNewConnectionValid(conn);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          if (firstException == null)
          {
            firstException = le;
          }

          continue;
        }
      }

      return conn;
    }

    throw firstException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DNSSRVRecordServerSet(recordName='");
    buffer.append(recordName);
    buffer.append("', providerURL='");
    buffer.append(providerURL);
    buffer.append("', ttlMillis=");
    buffer.append(ttlMillis);

    if (socketFactory != null)
    {
      buffer.append(", socketFactoryClass='");
      buffer.append(socketFactory.getClass().getName());
      buffer.append('\'');
    }

    if (connectionOptions != null)
    {
      buffer.append(", connectionOptions");
      connectionOptions.toString(buffer);
    }

    buffer.append(')');
  }
}
