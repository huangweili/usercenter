package com.hwlcn.ldap.ldap.sdk;



import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@InternalUseOnly()
final class LDAPConnectionInternals
{

  private final AtomicInteger nextMessageID;

  private final boolean synchronousMode;

  private final int port;

  private final long connectTime;

  private final LDAPConnection connection;

  private final LDAPConnectionReader connectionReader;

  private volatile OutputStream outputStream;

  private final Socket socket;

  private final String host;

  private static final ThreadLocal<ASN1Buffer> asn1Buffers =
       new ThreadLocal<ASN1Buffer>();




  LDAPConnectionInternals(final LDAPConnection connection,
                          final LDAPConnectionOptions options,
                          final SocketFactory socketFactory, final String host,
                          final int port, final int timeout)
       throws IOException

  {
    this.connection = connection;
    this.host       = host;
    this.port       = port;

    if (options.captureConnectStackTrace())
    {
      connection.setConnectStackTrace(Thread.currentThread().getStackTrace());
    }

    connectTime               = System.currentTimeMillis();
    nextMessageID             = new AtomicInteger(0);
    synchronousMode           = options.useSynchronousMode();

    try
    {
      final ConnectThread connectThread =
           new ConnectThread(socketFactory, host, port);
      connectThread.start();
      socket = connectThread.getConnectedSocket(timeout);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new IOException(le.getMessage());
    }

    if (options.getReceiveBufferSize() > 0)
    {
      socket.setReceiveBufferSize(options.getReceiveBufferSize());
    }

    if (options.getSendBufferSize() > 0)
    {
      socket.setSendBufferSize(options.getSendBufferSize());
    }

    try
    {
      debugConnect(host, port, connection);
      socket.setKeepAlive(options.useKeepAlive());
      socket.setReuseAddress(options.useReuseAddress());
      socket.setSoLinger(options.useLinger(),
                         options.getLingerTimeoutSeconds());
      socket.setTcpNoDelay(options.useTCPNoDelay());

      outputStream     = socket.getOutputStream();
      connectionReader = new LDAPConnectionReader(connection, this);
    }
    catch (IOException ioe)
    {
      debugException(ioe);
      try
      {
        socket.close();
      }
      catch (Exception e)
      {
        debugException(e);
      }

      throw ioe;
    }
  }


  void startConnectionReader()
  {
    if (! synchronousMode)
    {
      connectionReader.start();
    }
  }



  LDAPConnection getConnection()
  {
    return connection;
  }



  LDAPConnectionReader getConnectionReader()
  {
    return connectionReader;
  }


  String getHost()
  {
    return host;
  }



  int getPort()
  {
    return port;
  }



  Socket getSocket()
  {
    return socket;
  }



  OutputStream getOutputStream()
  {
    return outputStream;
  }



  boolean isConnected()
  {
    return socket.isConnected();
  }




  boolean synchronousMode()
  {
    return synchronousMode;
  }



  void convertToTLS(final SSLContext sslContext)
       throws LDAPException
  {
    outputStream = connectionReader.doStartTLS(sslContext);
  }


  int nextMessageID()
  {
    int msgID = nextMessageID.incrementAndGet();
    if (msgID > 0)
    {
      return msgID;
    }

    while (true)
    {
      if (nextMessageID.compareAndSet(msgID, 1))
      {
        return 1;
      }

      msgID = nextMessageID.incrementAndGet();
      if (msgID > 0)
      {
        return msgID;
      }
    }
  }




  void registerResponseAcceptor(final int messageID,
                                final ResponseAcceptor responseAcceptor)
       throws LDAPException
  {
    if (! isConnected())
    {
      final LDAPConnectionOptions connectionOptions =
           connection.getConnectionOptions();
      final boolean closeRequested = connection.closeRequested();
      if (connectionOptions.autoReconnect() && (! closeRequested))
      {
        connection.reconnect();
        connection.registerResponseAcceptor(messageID,  responseAcceptor);
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
                                ERR_CONN_NOT_ESTABLISHED.get());
      }
    }

    connectionReader.registerResponseAcceptor(messageID, responseAcceptor);
  }


  void deregisterResponseAcceptor(final int messageID)
  {
    connectionReader.deregisterResponseAcceptor(messageID);
  }




  void sendMessage(final LDAPMessage message, final boolean allowRetry)
       throws LDAPException
  {
    if (! isConnected())
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }

    ASN1Buffer buffer = asn1Buffers.get();
    if (buffer == null)
    {
      buffer = new ASN1Buffer();
      asn1Buffers.set(buffer);
    }

    buffer.clear();
    try
    {
      message.writeTo(buffer);
    }
    catch (final LDAPRuntimeException lre)
    {
      debugException(lre);
      lre.throwLDAPException();
    }

    try
    {
      final OutputStream os = outputStream;
      buffer.writeTo(os);
      os.flush();
    }
    catch (IOException ioe)
    {
      debugException(ioe);

      if (message.getProtocolOpType() ==
          LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST)
      {
        return;
      }

      final LDAPConnectionOptions connectionOptions =
           connection.getConnectionOptions();
      final boolean closeRequested = connection.closeRequested();
      if (allowRetry && (! closeRequested) && (! connection.synchronousMode()))
      {
        connection.reconnect();

        try
        {
          sendMessage(message, false);
          return;
        }
        catch (final Exception e)
        {
          debugException(e);
        }
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_SEND_ERROR.get(host + ':' + port, getExceptionMessage(ioe)),
           ioe);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONN_ENCODE_ERROR.get(host + ':' + port, getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (buffer.zeroBufferOnClear())
      {
        buffer.clear();
      }
    }
  }


  void close()
  {
    DisconnectInfo disconnectInfo = connection.getDisconnectInfo();
    if (disconnectInfo == null)
    {
      disconnectInfo = connection.setDisconnectInfo(
           new DisconnectInfo(connection, DisconnectType.UNKNOWN, null, null));
    }

     final boolean closedByFinalizer =
         ((disconnectInfo.getType() == DisconnectType.CLOSED_BY_FINALIZER) &&
          socket.isConnected());

    try
    {
      connectionReader.close(false);
    }
    catch (Exception e)
    {
      debugException(e);
    }

    try
    {
      outputStream.close();
    }
    catch (Exception e)
    {
      debugException(e);
    }

    try
    {
      socket.close();
    }
    catch (Exception e)
    {
      debugException(e);
    }

    debugDisconnect(host, port, connection, disconnectInfo.getType(),
         disconnectInfo.getMessage(), disconnectInfo.getCause());
    if (closedByFinalizer && debugEnabled(DebugType.LDAP))
    {
      debug(Level.WARNING, DebugType.LDAP,
            "Connection closed by LDAP SDK finalizer:  " + toString());
    }
    disconnectInfo.notifyDisconnectHandler();
  }



  public long getConnectTime()
  {
    if (isConnected())
    {
      return connectTime;
    }
    else
    {
      return -1L;
    }
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
    buffer.append("LDAPConnectionInternals(host='");
    buffer.append(host);
    buffer.append("', port=");
    buffer.append(port);
    buffer.append(", connected=");
    buffer.append(socket.isConnected());
    buffer.append(", nextMessageID=");
    buffer.append(nextMessageID.get());
    buffer.append(')');
  }
}
