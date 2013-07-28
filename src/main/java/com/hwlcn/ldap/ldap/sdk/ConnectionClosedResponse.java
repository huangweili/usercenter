package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class ConnectionClosedResponse
      implements LDAPResponse, Serializable
{
private static final long serialVersionUID = -3931112652935496193L;



  private final ResultCode resultCode;

  private final String message;



  ConnectionClosedResponse(final ResultCode resultCode,
                           final String message)
  {
    this.resultCode = resultCode;
    this.message    = message;
  }




  public int getMessageID()
  {
    return -1;
  }



  String getMessage()
  {
    return message;
  }



  ResultCode getResultCode()
  {
    return resultCode;
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("ConnectionClosedResponse(resultCode='");
    buffer.append(resultCode);
    buffer.append('\'');

    if (message != null)
    {
      buffer.append(", message='");
      buffer.append(message);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
