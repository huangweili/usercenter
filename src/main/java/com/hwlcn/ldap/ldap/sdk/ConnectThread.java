package com.hwlcn.ldap.ldap.sdk;



import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;




final class ConnectThread
      extends Thread
{
  private final AtomicBoolean connected;

  private final AtomicBoolean started;

  private final AtomicReference<Socket> socket;

  private final AtomicReference<Thread> thread;

  private final AtomicReference<Throwable> exception;

  private final int port;

  private final SocketFactory socketFactory;

  private final String address;



  ConnectThread(final SocketFactory socketFactory, final String address,
                final int port)
  {
    super("Background connect thread for " + address + ':' + port);
    setDaemon(true);

    this.socketFactory = socketFactory;
    this.address       = address;
    this.port          = port;

    connected = new AtomicBoolean(false);
    started   = new AtomicBoolean(false);
    socket    = new AtomicReference<Socket>();
    thread    = new AtomicReference<Thread>();
    exception = new AtomicReference<Throwable>();
  }


  @Override()
  public void run()
  {
    thread.set(Thread.currentThread());
    started.set(true);

    try
    {
      socket.set(socketFactory.createSocket(address, port));
      connected.set(true);
    }
    catch (final Throwable t)
    {
      debugException(t);
      exception.set(t);
    }
    finally
    {
      thread.set(null);
    }
  }



  Socket getConnectedSocket(final long timeoutMillis)
         throws LDAPException
  {
    while (! started.get())
    {
      Thread.yield();
    }

    final Thread t = thread.get();
    if (t != null)
    {
      try
      {
        t.join(timeoutMillis);
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }

    if (connected.get())
    {
      return socket.get();
    }

    try
    {
      if (t != null)
      {
        t.interrupt();
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    try
    {
      final Socket s = socket.get();
      if (s != null)
      {
        s.close();
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    final Throwable cause = exception.get();
    if (cause == null)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONNECT_THREAD_TIMEOUT.get(address, port, timeoutMillis));
    }
    else
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONNECT_THREAD_EXCEPTION.get(address, port,
                getExceptionMessage(cause)), cause);
    }
  }
}
