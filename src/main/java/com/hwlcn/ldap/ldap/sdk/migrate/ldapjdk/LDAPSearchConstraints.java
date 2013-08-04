
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPSearchConstraints
       extends LDAPConstraints
{

  private static final long serialVersionUID = -487551577157782460L;


  private int batchSize;

  private int derefPolicy;

  private int sizeLimit;

  private int timeLimit;


  public LDAPSearchConstraints()
  {
    super();

    batchSize   = 1;
    derefPolicy = LDAPConnection.DEREF_NEVER;
    sizeLimit   = 1000;
    timeLimit   = 0;
  }

  public LDAPSearchConstraints(final int msLimit, final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize, final LDAPRebind rebindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setRebindProc(rebindProc);
    setHopLimit(hopLimit);
  }



  public LDAPSearchConstraints(final int msLimit, final int timeLimit,
                               final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize, final LDAPRebind rebindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.timeLimit = timeLimit;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setRebindProc(rebindProc);
    setHopLimit(hopLimit);
  }


  public LDAPSearchConstraints(final int msLimit, final int timeLimit,
                               final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize, final LDAPBind bindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.timeLimit = timeLimit;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setBindProc(bindProc);
    setHopLimit(hopLimit);
  }

  public int getBatchSize()
  {
    return batchSize;
  }

  public void setBatchSize(final int batchSize)
  {
    if (batchSize < 1)
    {
      this.batchSize = 1;
    }
    else
    {
      this.batchSize = batchSize;
    }
  }


  public int getDereference()
  {
    return derefPolicy;
  }



  public void setDereference(final int dereference)
  {
    derefPolicy = dereference;
  }

  public int getMaxResults()
  {
    return sizeLimit;
  }



  public void setMaxResults(final int maxResults)
  {
    if (maxResults < 0)
    {
      sizeLimit = 0;
    }
    else
    {
      sizeLimit = maxResults;
    }
  }



  public int getServerTimeLimit()
  {
    return timeLimit;
  }


  public void setServerTimeLimit(final int limit)
  {
    if (limit < 0)
    {
      timeLimit = 0;
    }
    else
    {
      timeLimit = limit;
    }
  }


  @Override()
  public LDAPSearchConstraints duplicate()
  {
    final LDAPSearchConstraints c = new LDAPSearchConstraints();

    c.batchSize   = batchSize;
    c.derefPolicy = derefPolicy;
    c.sizeLimit   = sizeLimit;
    c.timeLimit   = timeLimit;

    c.setBindProc(getBindProc());
    c.setClientControls(getClientControls());
    c.setReferrals(getReferrals());
    c.setHopLimit(getHopLimit());
    c.setRebindProc(getRebindProc());
    c.setServerControls(getServerControls());
    c.setTimeLimit(getTimeLimit());

    return c;
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPSearchConstraints(constraints=");
    buffer.append(super.toString());
    buffer.append(", batchSize=");
    buffer.append(batchSize);
    buffer.append(", derefPolicy=");
    buffer.append(derefPolicy);
    buffer.append(", maxResults=");
    buffer.append(sizeLimit);
    buffer.append(", serverTimeLimit=");
    buffer.append(timeLimit);
    buffer.append(')');

    return buffer.toString();
  }
}
