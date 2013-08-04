
package com.hwlcn.ldap.util.parallel;



import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ResultProcessor<I, O>
{

  void processResult(Result<I, O> result)
       throws Exception;
}
