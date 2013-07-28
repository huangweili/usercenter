package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetEntryLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
       implements Serializable
{

  private static final long DEFAULT_MAX_RESPONSE_TIME = 30000L;


  private static final long serialVersionUID = -3400259782503254645L;



  private final boolean invokeForBackgroundChecks;

  private final boolean invokeOnCheckout;

  private final boolean invokeOnCreate;

  private final boolean invokeOnException;

  private final boolean invokeOnRelease;

  private final long maxResponseTime;

  private final SearchRequest searchRequest;

  private final String entryDN;



  public GetEntryLDAPConnectionPoolHealthCheck(final String entryDN,
              final long maxResponseTime, final boolean invokeOnCreate,
              final boolean invokeOnCheckout, final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException)
  {
    this.invokeOnCreate            = invokeOnCreate;
    this.invokeOnCheckout          = invokeOnCheckout;
    this.invokeOnRelease           = invokeOnRelease;
    this.invokeForBackgroundChecks = invokeForBackgroundChecks;
    this.invokeOnException         = invokeOnException;

    if (entryDN == null)
    {
      this.entryDN = "";
    }
    else
    {
      this.entryDN = entryDN;
    }

    if (maxResponseTime > 0L)
    {
      this.maxResponseTime = maxResponseTime;
    }
    else
    {
      this.maxResponseTime = DEFAULT_MAX_RESPONSE_TIME;
    }

    searchRequest = new SearchRequest(this.entryDN, SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"), "1.1");
    searchRequest.setResponseTimeoutMillis(this.maxResponseTime);
  }


  @Override()
  public void ensureNewConnectionValid(final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnCreate)
    {
      getEntry(connection);
    }
  }



  @Override()
  public void ensureConnectionValidForCheckout(final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnCheckout)
    {
      getEntry(connection);
    }
  }



  @Override()
  public void ensureConnectionValidForRelease(final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnRelease)
    {
      getEntry(connection);
    }
  }



  @Override()
  public void ensureConnectionValidForContinuedUse(
                   final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeForBackgroundChecks)
    {
      getEntry(connection);
    }
  }



  @Override()
  public void ensureConnectionValidAfterException(
                   final LDAPConnection connection,
                   final LDAPException exception)
         throws LDAPException
  {
    super.ensureConnectionValidAfterException(connection, exception);

    if (invokeOnException)
    {
      getEntry(connection);
    }
  }



  public String getEntryDN()
  {
    return entryDN;
  }



  public long getMaxResponseTimeMillis()
  {
    return maxResponseTime;
  }



  public boolean invokeOnCreate()
  {
    return invokeOnCreate;
  }


  public boolean invokeOnCheckout()
  {
    return invokeOnCheckout;
  }



  public boolean invokeOnRelease()
  {
    return invokeOnRelease;
  }



  public boolean invokeForBackgroundChecks()
  {
    return invokeForBackgroundChecks;
  }



  public boolean invokeOnException()
  {
    return invokeOnException;
  }




  private void getEntry(final LDAPConnection conn)
          throws LDAPException
  {
    try
    {
      final SearchResult result = conn.search(searchRequest);
      if (result.getEntryCount() != 1)
      {
        throw new LDAPException(ResultCode.NO_RESULTS_RETURNED,
             ERR_GET_ENTRY_HEALTH_CHECK_NO_ENTRY_RETURNED.get());
      }
    }
    catch (Exception e)
    {
      debugException(e);

      final String msg = ERR_GET_ENTRY_HEALTH_CHECK_FAILURE.get(entryDN,
           getExceptionMessage(e));

      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, msg, e);
      throw new LDAPException(ResultCode.SERVER_DOWN, msg, e);
    }
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GetEntryLDAPConnectionPoolHealthCheck(entryDN='");
    buffer.append(entryDN);
    buffer.append("', maxResponseTimeMillis=");
    buffer.append(maxResponseTime);
    buffer.append(", invokeOnCreate=");
    buffer.append(invokeOnCreate);
    buffer.append(", invokeOnCheckout=");
    buffer.append(invokeOnCheckout);
    buffer.append(", invokeOnRelease=");
    buffer.append(invokeOnRelease);
    buffer.append(", invokeForBackgroundChecks=");
    buffer.append(invokeForBackgroundChecks);
    buffer.append(", invokeOnException=");
    buffer.append(invokeOnException);
    buffer.append(')');
  }
}
