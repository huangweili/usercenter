package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPConstraints
       implements Serializable
{
  private static final long serialVersionUID = 6843729471197926148L;

  private boolean followReferrals;
  private int hopLimit;
  private int timeLimit;

  private LDAPBind bindProc;

  private LDAPControl[] clientControls;

  private LDAPControl[] serverControls;

  private LDAPRebind rebindProc;


  public LDAPConstraints()
  {
    bindProc        = null;
    clientControls  = new LDAPControl[0];
    followReferrals = false;
    hopLimit        = 5;
    rebindProc      = null;
    serverControls  = new LDAPControl[0];
    timeLimit       = 0;
  }


  public LDAPConstraints(final int msLimit, final boolean doReferrals,
                         final LDAPBind bindProc, final int hopLimit)
  {
    this();

    timeLimit       = msLimit;
    followReferrals = doReferrals;
    this.bindProc   = bindProc;
    this.hopLimit   = hopLimit;
  }


  public LDAPConstraints(final int msLimit, final boolean doReferrals,
                         final LDAPRebind rebindProc, final int hopLimit)
  {
    this();

    timeLimit       = msLimit;
    followReferrals = doReferrals;
    this.rebindProc = rebindProc;
    this.hopLimit   = hopLimit;
  }


  public int getTimeLimit()
  {
    return timeLimit;
  }


  public void setTimeLimit(final int timeLimit)
  {
    if (timeLimit < 0)
    {
      this.timeLimit = 0;
    }
    else
    {
      this.timeLimit = timeLimit;
    }
  }


  public boolean getReferrals()
  {
    return followReferrals;
  }

  public void setReferrals(final boolean doReferrals)
  {
    followReferrals = doReferrals;
  }


  public LDAPBind getBindProc()
  {
    return bindProc;
  }

  public void setBindProc(final LDAPBind bindProc)
  {
    this.bindProc = bindProc;
  }

  public LDAPRebind getRebindProc()
  {
    return rebindProc;
  }

  public void setRebindProc(final LDAPRebind rebindProc)
  {
    this.rebindProc = rebindProc;
  }


  public int getHopLimit()
  {
    return hopLimit;
  }

  public void setHopLimit(final int hopLimit)
  {
    if (hopLimit < 0)
    {
      this.hopLimit = 0;
    }
    else
    {
      this.hopLimit = hopLimit;
    }
  }


  public LDAPControl[] getClientControls()
  {
    return clientControls;
  }


  public void setClientControls(final LDAPControl control)
  {
    clientControls = new LDAPControl[] { control };
  }

  public void setClientControls(final LDAPControl[] controls)
  {
    if (controls == null)
    {
      clientControls = new LDAPControl[0];
    }
    else
    {
      clientControls = controls;
    }
  }


  public LDAPControl[] getServerControls()
  {
    return serverControls;
  }


  public void setServerControls(final LDAPControl control)
  {
    serverControls = new LDAPControl[] { control };
  }


  public void setServerControls(final LDAPControl[] controls)
  {
    if (controls == null)
    {
      serverControls = new LDAPControl[0];
    }
    else
    {
      serverControls = controls;
    }
  }


  public LDAPConstraints duplicate()
  {
    final LDAPConstraints c = new LDAPConstraints();

    c.bindProc        = bindProc;
    c.clientControls  = clientControls;
    c.followReferrals = followReferrals;
    c.hopLimit        = hopLimit;
    c.rebindProc      = rebindProc;
    c.serverControls  = serverControls;
    c.timeLimit       = timeLimit;

    return c;
  }

  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPConstraints(followReferrals=");
    buffer.append(followReferrals);
    buffer.append(", bindProc=");
    buffer.append(String.valueOf(bindProc));
    buffer.append(", rebindProc=");
    buffer.append(String.valueOf(rebindProc));
    buffer.append(", hopLimit=");
    buffer.append(hopLimit);
    buffer.append(", timeLimit=");
    buffer.append(timeLimit);
    buffer.append(", clientControls={");

    for (int i=0; i < clientControls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(clientControls[i].toString());
    }

    buffer.append("}, serverControls={");

    for (int i=0; i < serverControls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(serverControls[i].toString());
    }

    buffer.append("})");

    return buffer.toString();
  }
}
