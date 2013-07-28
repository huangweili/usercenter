package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.atomic.AtomicBoolean;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class DisconnectInfo
{
  private final AtomicBoolean handlerNotified;

  private final DisconnectType type;

  private final int port;

  private final LDAPConnection connection;

  private final String host;

  private final String message;

  private final Throwable cause;




  DisconnectInfo(final LDAPConnection connection, final DisconnectType type,
                 final String message, final Throwable cause)
  {
    Validator.ensureNotNull(connection);
    Validator.ensureNotNull(type);

    this.connection = connection;
    this.type       = type;
    this.message    = message;
    this.cause      = cause;

    handlerNotified = new AtomicBoolean(false);
    host = connection.getConnectedAddress();
    port = connection.getConnectedPort();
  }




  DisconnectType getType()
  {
    return type;
  }




  String getMessage()
  {
    return message;
  }




  Throwable getCause()
  {
    return cause;
  }




  void notifyDisconnectHandler()
  {
    final boolean alreadyNotified = handlerNotified.getAndSet(true);
    if (alreadyNotified)
    {
      return;
    }

    final DisconnectHandler handler =
         connection.getConnectionOptions().getDisconnectHandler();
    if (handler != null)
    {
      handler.handleDisconnect(connection, host, port, type, message, cause);
    }
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  void toString(final StringBuilder buffer)
  {
    buffer.append("DisconnectInfo(type=");
    buffer.append(type.name());

    if (message != null)
    {
      buffer.append(", message='");
      buffer.append(message);
      buffer.append('\'');
    }

    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(StaticUtils.getExceptionMessage(cause));
    }

    buffer.append(')');
  }
}
