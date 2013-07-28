package com.hwlcn.ldap.ldap.sdk;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class LDAPRequest
       implements ReadOnlyLDAPRequest
{
  static final Control[] NO_CONTROLS = new Control[0];

  private static final long serialVersionUID = -2040756188243320117L;


  private Boolean followReferrals;

  private Control[] controls;

  private IntermediateResponseListener intermediateResponseListener;

  private long responseTimeout;


  protected LDAPRequest(final Control[] controls)
  {
    if (controls == null)
    {
      this.controls = NO_CONTROLS;
    }
    else
    {
      this.controls = controls;
    }

    followReferrals = null;
    responseTimeout = -1L;
    intermediateResponseListener = null;
  }




  public final Control[] getControls()
  {
    return controls;
  }



  public final List<Control> getControlList()
  {
    return Collections.unmodifiableList(Arrays.asList(controls));
  }


  public final boolean hasControl()
  {
    return (controls.length > 0);
  }

  public final boolean hasControl(final String oid)
  {
    ensureNotNull(oid);

    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return true;
      }
    }

    return false;
  }

  public final Control getControl(final String oid)
  {
    ensureNotNull(oid);

    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }


  final void setControlsInternal(final Control[] controls)
  {
    this.controls = controls;
  }


  public final long getResponseTimeoutMillis(final LDAPConnection connection)
  {
    if ((responseTimeout < 0L) && (connection != null))
    {
      return connection.getConnectionOptions().getResponseTimeoutMillis();
    }
    else
    {
      return responseTimeout;
    }
  }


  public final void setResponseTimeoutMillis(final long responseTimeout)
  {
    if (responseTimeout < 0L)
    {
      this.responseTimeout = -1L;
    }
    else
    {
      this.responseTimeout = responseTimeout;
    }
  }



  public final boolean followReferrals(final LDAPConnection connection)
  {
    if (followReferrals == null)
    {
      return connection.getConnectionOptions().followReferrals();
    }
    else
    {
      return followReferrals;
    }
  }

  final Boolean followReferralsInternal()
  {
    return followReferrals;
  }

  public final void setFollowReferrals(final Boolean followReferrals)
  {
    this.followReferrals = followReferrals;
  }

  public final IntermediateResponseListener getIntermediateResponseListener()
  {
    return intermediateResponseListener;
  }

  public final void setIntermediateResponseListener(
                         final IntermediateResponseListener listener)
  {
    intermediateResponseListener = listener;
  }

  @InternalUseOnly()
  protected abstract LDAPResult process(final LDAPConnection connection,
                                        final int depth)
            throws LDAPException;


  public abstract int getLastMessageID();

  public abstract OperationType getOperationType();

  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public abstract void toString(final StringBuilder buffer);
}
