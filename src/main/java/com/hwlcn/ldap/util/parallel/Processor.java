
package com.hwlcn.ldap.util.parallel;



import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface Processor<I,O>
{

  O process(I input) throws Throwable;
}
