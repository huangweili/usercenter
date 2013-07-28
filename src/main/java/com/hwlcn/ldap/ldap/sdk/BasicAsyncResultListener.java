package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BasicAsyncResultListener
       implements AsyncResultListener, Serializable
{

  private static final long serialVersionUID = -2701328904233458257L;



  private volatile LDAPResult ldapResult;



  public BasicAsyncResultListener()
  {
    ldapResult = null;
  }



  @InternalUseOnly()
  public void ldapResultReceived(final AsyncRequestID requestID,
                                 final LDAPResult ldapResult)
  {
    this.ldapResult = ldapResult;
  }


 public LDAPResult getLDAPResult()
  {
    return ldapResult;
  }
}
