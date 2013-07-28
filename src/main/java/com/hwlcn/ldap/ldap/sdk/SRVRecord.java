package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.StringTokenizer;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecord
      implements Serializable
{

  private static final long serialVersionUID = -5505867807717870889L;


  private final int port;

  private final long priority;

  private final long weight;

  private final String address;

  private final String recordString;



  SRVRecord(final String recordString)
       throws LDAPException
  {
    this.recordString = recordString;

    try
    {
      final StringTokenizer tokenizer = new StringTokenizer(recordString, " ");
      priority = Long.parseLong(tokenizer.nextToken());
      weight   = Long.parseLong(tokenizer.nextToken());
      port     = Integer.parseInt(tokenizer.nextToken());

      final String addrString = tokenizer.nextToken();
      if (addrString.endsWith("."))
      {
        address = addrString.substring(0, addrString.length() - 1);
      }
      else
      {
        address = addrString;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_MALFORMED_STRING.get(recordString,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }


  public String getAddress()
  {
    return address;
  }


  public int getPort()
  {
    return port;
  }


  public long getPriority()
  {
    return priority;
  }

  public long getWeight()
  {
    return weight;
  }


  @Override()
  public String toString()
  {
    return recordString;
  }
}
