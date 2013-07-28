package com.hwlcn.ldap.util.args;



import com.hwlcn.ldap.util.LDAPSDKException;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ArgumentException
       extends LDAPSDKException
{

  private static final long serialVersionUID = 8353938257797371099L;



  public ArgumentException(final String message)
  {
    super(message);
  }


  public ArgumentException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
