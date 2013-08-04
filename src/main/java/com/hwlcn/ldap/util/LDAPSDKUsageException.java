
package com.hwlcn.ldap.util;


import com.hwlcn.HwlcnException;
import com.hwlcn.core.annotation.ThreadSafety;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSDKUsageException
       extends HwlcnException
{

  private static final long serialVersionUID = 4488711069492709961L;




  public LDAPSDKUsageException(final String message)
  {
    super(message);
  }



  public LDAPSDKUsageException(final String message, final Throwable cause)
  {
    super(message, cause);
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPSDKUsageException(message='");
    buffer.append(getMessage());
    buffer.append('\'');

    final Throwable cause = getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(cause.toString());
    }

    buffer.append(')');
  }
}
