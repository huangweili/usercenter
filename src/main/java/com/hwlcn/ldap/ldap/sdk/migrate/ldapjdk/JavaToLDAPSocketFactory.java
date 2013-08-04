
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JavaToLDAPSocketFactory
       extends SocketFactory
       implements LDAPSocketFactory
{

  private final SocketFactory f;

  public JavaToLDAPSocketFactory(final SocketFactory f)
  {
    this.f = f;
  }

  @Override()
  public Socket createSocket(final String host, final int port)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(host, port);
    }
  }

  @Override()
  public Socket createSocket(final String host, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(host, port, localAddress, localPort);
    }
  }

  @Override()
  public Socket createSocket(final InetAddress address, final int port)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(address, port);
    }
  }

  @Override()
  public Socket createSocket(final InetAddress address, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(address, port, localAddress, localPort);
    }
  }

  public Socket makeSocket(final String host, final int port)
         throws LDAPException
  {
    try
    {
      synchronized (f)
      {
        return f.createSocket(host, port);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(getExceptionMessage(e),
           LDAPException.CONNECT_ERROR);
    }
  }
}
