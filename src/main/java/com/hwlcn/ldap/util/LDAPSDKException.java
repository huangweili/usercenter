package com.hwlcn.ldap.util;


import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;

@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class LDAPSDKException
       extends Exception
{

  protected LDAPSDKException(final String message)
  {
    super(message);
  }


  protected LDAPSDKException(final String message, final Throwable cause)
  {
    super(message, cause);
  }


  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public void toString(final StringBuilder buffer)
  {
    buffer.append(super.toString());
  }



  public String getExceptionMessage()
  {
    final String message = getMessage();
    if (message == null)
    {
      return toString();
    }
    else
    {
      return message;
    }
  }
}
