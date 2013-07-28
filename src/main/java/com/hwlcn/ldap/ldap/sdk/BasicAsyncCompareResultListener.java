package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BasicAsyncCompareResultListener
       implements AsyncCompareResultListener, Serializable
{

  private static final long serialVersionUID = 8119461093491566432L;



  private volatile CompareResult compareResult;


  public BasicAsyncCompareResultListener()
  {
    compareResult = null;
  }


  @InternalUseOnly()
  public void compareResultReceived(final AsyncRequestID requestID,
                                    final CompareResult compareResult)
  {
    this.compareResult = compareResult;
  }




  public CompareResult getCompareResult()
  {
    return compareResult;
  }
}
