
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;




@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SynchronizedSocketFactory
       extends SocketFactory
{
  private final SocketFactory factory;




  public SynchronizedSocketFactory(final SocketFactory factory)
  {
    this.factory = factory;
  }



  public SocketFactory getWrappedSocketFactory()
  {
    return factory;
  }



  @Override()
  public Socket createSocket(final String host, final int port)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(host, port);
    }
  }


  @Override()
  public Socket createSocket(final String host, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(host, port, localAddress, localPort);
    }
  }


  @Override()
  public Socket createSocket(final InetAddress address, final int port)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(address, port);
    }
  }



  @Override()
  public Socket createSocket(final InetAddress address, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(address, port, localAddress, localPort);
    }
  }
}
