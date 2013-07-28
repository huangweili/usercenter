package com.hwlcn.ldap.ldap.sdk;



import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.ldap.util.WakeableSleeper;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@InternalUseOnly()
final class LDAPConnectionReader
      extends Thread
{

  private static final int DEFAULT_INPUT_BUFFER_SIZE = 4096;



  private volatile ASN1StreamReader asn1StreamReader;

  private volatile boolean closeRequested;

  private final ConcurrentHashMap<Integer,ResponseAcceptor> acceptorMap;

  private volatile Exception startTLSException;

  private volatile InputStream inputStream;

  private volatile OutputStream startTLSOutputStream;

  private final LDAPConnection connection;

  private volatile Socket socket;


  private volatile SSLContext sslContext;

  private volatile Thread thread;

  private final WakeableSleeper startTLSSleeper;



  LDAPConnectionReader(final LDAPConnection connection,
                       final LDAPConnectionInternals connectionInternals)
       throws IOException
  {
    this.connection = connection;

    setName(constructThreadName(connectionInternals));
    setDaemon(true);

    socket               = connectionInternals.getSocket();
    inputStream          = new BufferedInputStream(socket.getInputStream(),
                                                   DEFAULT_INPUT_BUFFER_SIZE);
    asn1StreamReader = new ASN1StreamReader(inputStream,
         connection.getConnectionOptions().getMaxMessageSize());

    acceptorMap          = new ConcurrentHashMap<Integer,ResponseAcceptor>();
    closeRequested       = false;
    sslContext           = null;
    startTLSException    = null;
    startTLSOutputStream = null;
    startTLSSleeper      = new WakeableSleeper();

    if (! connectionInternals.synchronousMode())
    {

      final LDAPConnectionOptions options = connection.getConnectionOptions();
      final int connectTimeout = options.getConnectTimeoutMillis();
      if (connectTimeout > 0)
      {
        if (debugEnabled())
        {
          debug(Level.INFO, DebugType.CONNECT,
               "Setting SO_TIMEOUT to connect timeout of " + connectTimeout +
                    "ms in LDAPConnectionReader constructor");
        }
        socket.setSoTimeout(connectTimeout);
      }
      else
      {
        if (debugEnabled())
        {
          debug(Level.INFO, DebugType.CONNECT,
               "Setting SO_TIMEOUT to 0ms in LDAPConnectionReader " +
                    "constructor");
        }
        socket.setSoTimeout(0);
      }

      if (socket instanceof SSLSocket)
      {
        final SSLSocket sslSocket = (SSLSocket) socket;
        sslSocket.startHandshake();
      }
    }
  }



  void registerResponseAcceptor(final int messageID,
                                final ResponseAcceptor acceptor)
       throws LDAPException
  {
    if (acceptorMap.putIfAbsent(messageID, acceptor) != null)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
                              ERR_CONNREADER_MSGID_IN_USE.get());
    }
  }




  void deregisterResponseAcceptor(final int messageID)
  {
    acceptorMap.remove(messageID);
  }



  int getActiveOperationCount()
  {
    return acceptorMap.size();
  }

  @Override()
  public void run()
  {
    boolean reconnect  = false;

    thread = Thread.currentThread();

    while (! closeRequested)
    {
      try
      {
        final LDAPResponse response;
        try
        {
          response = LDAPMessage.readLDAPResponseFrom(asn1StreamReader, true,
               connection.getCachedSchema());
        }
        catch (LDAPException le)
        {
          final Throwable t = le.getCause();
          if ((t != null) && (t instanceof SocketTimeoutException))
          {
            final SocketTimeoutException ste = (SocketTimeoutException) t;
            debugException(Level.FINEST,  ste);
            if (sslContext != null)
            {
              try
              {
                final int connectTimeout = connection.getConnectionOptions().
                     getConnectTimeoutMillis();
                if (connectTimeout > 0)
                {
                  if (debugEnabled())
                  {
                    debug(Level.INFO, DebugType.CONNECT,
                         "Setting SO_TIMEOUT to connect timeout of " +
                              connectTimeout + "ms in " +
                              "LDAPConnectionReader.run while performing " +
                              "StartTLS processing.");
                  }
                  socket.setSoTimeout(connectTimeout);
                }
                else
                {
                  if (debugEnabled())
                  {
                    debug(Level.INFO, DebugType.CONNECT,
                         "Setting SO_TIMEOUT to 0ms in " +
                              "LDAPConnectionReader.run while performing " +
                              "StartTLS processing.");
                  }
                  socket.setSoTimeout(0);
                }

                final SSLSocket sslSocket;
                final SSLSocketFactory socketFactory =
                     sslContext.getSocketFactory();
                synchronized (socketFactory)
                {
                  sslSocket = (SSLSocket) socketFactory.createSocket(socket,
                       connection.getConnectedAddress(), socket.getPort(),
                       true);
                  sslSocket.startHandshake();
                }
                inputStream =
                     new BufferedInputStream(sslSocket.getInputStream(),
                                             DEFAULT_INPUT_BUFFER_SIZE);
                asn1StreamReader = new ASN1StreamReader(inputStream,
                     connection.getConnectionOptions().getMaxMessageSize());
                startTLSOutputStream = sslSocket.getOutputStream();
                socket = sslSocket;
                startTLSSleeper.wakeup();
              }
              catch (Exception e)
              {
                debugException(e);
                connection.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM,
                     getExceptionMessage(e), e);
                startTLSException = e;
                closeRequested = true;
                if (thread != null)
                {
                  thread.setName(thread.getName() + " (closed)");
                  thread = null;
                }
                closeInternal(true, getExceptionMessage(e));
                startTLSSleeper.wakeup();
                return;
              }

              sslContext = null;
            }

            continue;
          }

          if (closeRequested || connection.closeRequested() ||
              (connection.getDisconnectType() != null))
          {
          closeRequested = true;
            debugException(Level.FINEST, le);
          }
          else
          {
            debugException(le);
          }

          final String message;
          Level debugLevel = Level.SEVERE;

          if (t == null)
          {
            connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
                 le.getMessage(), t);
            message = le.getMessage();
            debugLevel = Level.WARNING;
          }
          else if ((t instanceof InterruptedIOException) && socket.isClosed())
          {
            connection.setDisconnectInfo(
                 DisconnectType.SERVER_CLOSED_WITHOUT_NOTICE, le.getMessage(),
                 t);
            message = ERR_READER_CLOSING_DUE_TO_INTERRUPTED_IO.get(
                 connection.getHostPort());
            debugLevel = Level.WARNING;
          }
          else if (t instanceof IOException)
          {
            connection.setDisconnectInfo(DisconnectType.IO_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
                 connection.getHostPort(), getExceptionMessage(t));
            debugLevel = Level.WARNING;
          }
          else if (t instanceof ASN1Exception)
          {
            connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
                 connection.getHostPort(), getExceptionMessage(t));
          }
          else
          {
            connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
                 connection.getHostPort(), getExceptionMessage(t));
          }

          debug(debugLevel, DebugType.LDAP, message, t);

           if ((! closeRequested) &&
              connection.getConnectionOptions().autoReconnect())
          {
            reconnect = true;
            break;
          }
          else
          {
            closeRequested = true;
            if (thread != null)
            {
              thread.setName(thread.getName() + " (closed)");
              thread = null;
            }
            closeInternal(true, message);
            return;
          }
        }

        if (response == null)
        {
           connection.setDisconnectInfo(
               DisconnectType.SERVER_CLOSED_WITHOUT_NOTICE, null, null);
          if ((! closeRequested) && (! connection.unbindRequestSent()) &&
              connection.getConnectionOptions().autoReconnect())
          {
            reconnect = true;
            break;
          }
          else
          {
            closeRequested = true;
            if (thread != null)
            {
              thread.setName(thread.getName() + " (closed)");
              thread = null;
            }
            closeInternal(true, null);
            return;
          }
        }

        debugLDAPResult(response, connection);

        final ResponseAcceptor responseAcceptor;
        if ((response instanceof SearchResultEntry) ||
            (response instanceof SearchResultReference))
        {
          responseAcceptor = acceptorMap.get(response.getMessageID());
        }
        else if (response instanceof IntermediateResponse)
        {
          final IntermediateResponse ir = (IntermediateResponse) response;
          responseAcceptor = acceptorMap.get(response.getMessageID());
           IntermediateResponseListener l = null;
          if (responseAcceptor instanceof LDAPRequest)
          {
            final LDAPRequest r = (LDAPRequest) responseAcceptor;
            l = r.getIntermediateResponseListener();

          }
          else if (responseAcceptor instanceof IntermediateResponseListener)
          {
            l = (IntermediateResponseListener) responseAcceptor;
          }

          if (l == null)
          {
            debug(Level.WARNING, DebugType.LDAP,
                  WARN_INTERMEDIATE_RESPONSE_WITH_NO_LISTENER.get(
                       String.valueOf(ir)));
          }
          else
          {
            try
            {
              l.intermediateResponseReturned(ir);
            }
            catch (Exception e)
            {
              debugException(e);
            }
          }
          continue;
        }
        else
        {
          responseAcceptor = acceptorMap.remove(response.getMessageID());
        }


        if (responseAcceptor == null)
        {
          if ((response instanceof ExtendedResult) &&
              (response.getMessageID() == 0))
          {
             ExtendedResult extendedResult = (ExtendedResult) response;

            final String oid = extendedResult.getOID();
            if (NoticeOfDisconnectionExtendedResult.
                     NOTICE_OF_DISCONNECTION_RESULT_OID.equals(oid))
            {
              extendedResult = new NoticeOfDisconnectionExtendedResult(
                                        extendedResult);
              connection.setDisconnectInfo(
                   DisconnectType.SERVER_CLOSED_WITH_NOTICE,
                   extendedResult.getDiagnosticMessage(), null);
            }
            else if ("1.3.6.1.4.1.30221.2.6.5".equals(oid))
            {
              try
              {
                final Class<?> c = Class.forName("com.hwlcn.ldap.ldap.sdk." +
                     "unboundidds.extensions." +
                     "InteractiveTransactionAbortedExtendedResult");
                final Constructor<?> ctor =
                     c.getConstructor(ExtendedResult.class);
                extendedResult =
                     (ExtendedResult) ctor.newInstance(extendedResult);
              }
              catch (Exception e)
              {
               debugException(e);
              }
            }

            final UnsolicitedNotificationHandler handler =
                 connection.getConnectionOptions().
                      getUnsolicitedNotificationHandler();
            if (handler == null)
            {
              if (debugEnabled(DebugType.LDAP))
              {
                debug(Level.WARNING, DebugType.LDAP,
                     WARN_READER_UNHANDLED_UNSOLICITED_NOTIFICATION.get(
                          response));
              }
            }
            else
            {
              handler.handleUnsolicitedNotification(connection,
                                                    extendedResult);
            }
            continue;
          }

          if (debugEnabled(DebugType.LDAP))
          {
            debug(Level.WARNING, DebugType.LDAP,
                  WARN_READER_NO_ACCEPTOR.get(response));
          }
          continue;
        }

        try
        {
          responseAcceptor.responseReceived(response);
        }
        catch (LDAPException le)
        {
          debugException(le);
          debug(Level.WARNING, DebugType.LDAP,
                ERR_READER_ACCEPTOR_ERROR.get(String.valueOf(response),
                     connection.getHostPort(), getExceptionMessage(le)), le);
        }
      }
      catch (Exception e)
      {
        debugException(e);


        final String message;
        Level debugLevel = Level.SEVERE;
        if (e instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
          debugLevel = Level.WARNING;
        }
        else if (e instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
        }

        debug(debugLevel, DebugType.LDAP, message, e);

        if (connection.getConnectionOptions().autoReconnect())
        {
          reconnect = true;
          break;
        }
        else
        {
          closeRequested = true;
          if (thread != null)
          {
            thread.setName(thread.getName() + " (closed)");
            thread = null;
          }
          closeInternal(true, message);
          return;
        }
      }
    }

    if (thread != null)
    {
      thread.setName(constructThreadName(null));
      thread = null;
    }

    if (reconnect && (! connection.closeRequested()))
    {
      try
      {
        connection.setNeedsReconnect();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
    else
    {
      closeInternal(true, null);
    }
  }




  LDAPResponse readResponse(final int messageID)
               throws LDAPException
  {
    while (true)
    {
      try
      {
        final LDAPResponse response = LDAPMessage.readLDAPResponseFrom(
             asn1StreamReader, false, connection.getCachedSchema());
        if (response == null)
        {
          return new ConnectionClosedResponse(ResultCode.SERVER_DOWN, null);
        }

        if (response.getMessageID() == messageID)
        {
          return response;
        }

        if ((response instanceof ExtendedResult) &&
            (response.getMessageID() == 0))
        {

          ExtendedResult extendedResult = (ExtendedResult) response;

          final String oid = extendedResult.getOID();
          if (NoticeOfDisconnectionExtendedResult.
                   NOTICE_OF_DISCONNECTION_RESULT_OID.equals(oid))
          {
            extendedResult = new NoticeOfDisconnectionExtendedResult(
                                      extendedResult);
            connection.setDisconnectInfo(
                 DisconnectType.SERVER_CLOSED_WITH_NOTICE,
                 extendedResult.getDiagnosticMessage(), null);
          }
          else if ("1.3.6.1.4.1.30221.2.6.5".equals(oid))
          {
            try
            {
              final Class<?> c = Class.forName("com.hwlcn.ldap.ldap.sdk." +
                   "unboundidds.extensions." +
                   "InteractiveTransactionAbortedExtendedResult");
              final Constructor<?> ctor =
                   c.getConstructor(ExtendedResult.class);
              extendedResult =
                   (ExtendedResult) ctor.newInstance(extendedResult);
            }
            catch (Exception e)
            {

              debugException(e);
            }
          }

          final UnsolicitedNotificationHandler handler =
               connection.getConnectionOptions().
                    getUnsolicitedNotificationHandler();
          if (handler == null)
          {
            if (debugEnabled(DebugType.LDAP))
            {
              debug(Level.WARNING, DebugType.LDAP,
                   WARN_READER_UNHANDLED_UNSOLICITED_NOTIFICATION.get(
                        response));
            }
          }
          else
          {
            handler.handleUnsolicitedNotification(connection,
                                                  extendedResult);
          }
          continue;
        }

        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.WARNING, DebugType.LDAP,
                WARN_READER_DISCARDING_UNEXPECTED_RESPONSE.get(response,
                     messageID));
        }
      }
      catch (LDAPException le)
      {
        debugException(le);
        final Throwable t = le.getCause();

          if ((t != null) && (t instanceof SocketTimeoutException))
        {
          throw new LDAPException(ResultCode.TIMEOUT, le.getMessage(), le);
        }


        final String message;
        Level debugLevel = Level.SEVERE;

        if (t == null)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
               le.getMessage(), t);
          message = le.getMessage();
          debugLevel = Level.WARNING;
        }
        else if (t instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(t));
          debugLevel = Level.WARNING;
        }
        else if (t instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(t));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(t));
        }

        debug(debugLevel, DebugType.LDAP, message, t);
        if (! connection.getConnectionOptions().autoReconnect())
        {
          closeRequested = true;
        }
        closeInternal(true, message);
        throw le;
      }
      catch (Exception e)
      {
        debugException(e);

        final String message;
        Level debugLevel = Level.SEVERE;
        if (e instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
          debugLevel = Level.WARNING;
        }
        else if (e instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), getExceptionMessage(e));
        }

        debug(debugLevel, DebugType.LDAP, message, e);
        if (! connection.getConnectionOptions().autoReconnect())
        {
          closeRequested = true;
        }
        closeInternal(true, message);
        throw new LDAPException(ResultCode.SERVER_DOWN,  message, e);
      }
    }
  }




  void setSoTimeout(final int soTimeout)
       throws LDAPException
  {
    try
    {
      socket.setSoTimeout(soTimeout);
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_READER_CANNOT_SET_SO_TIMEOUT.get(soTimeout,
                connection.toString(), getExceptionMessage(e)),
           e);
    }
  }



  OutputStream doStartTLS(final SSLContext sslContext)
       throws LDAPException
  {
    if (connection.synchronousMode())
    {
      try
      {
        final int connectTimeout = connection.getConnectionOptions().
             getConnectTimeoutMillis();
        if (connectTimeout > 0)
        {
          if (debugEnabled())
          {
            debug(Level.INFO, DebugType.CONNECT,
                 "Setting SO_TIMEOUT to connect timeout of " +
                      connectTimeout + "ms in " +
                      "LDAPConnectionReader.doStartTLS while performing " +
                      "StartTLS processing.");
          }
          socket.setSoTimeout(connectTimeout);
        }
        else
        {
          if (debugEnabled())
          {
            debug(Level.INFO, DebugType.CONNECT,
                 "Setting SO_TIMEOUT to 0ms in " +
                      "LDAPConnectionReader.doStartTLS while performing " +
                      "StartTLS processing.");
          }
          socket.setSoTimeout(0);
        }

        final SSLSocket sslSocket;
        final SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        synchronized (socketFactory)
        {
          sslSocket = (SSLSocket) socketFactory.createSocket(socket,
               connection.getConnectedAddress(), socket.getPort(), true);
          sslSocket.startHandshake();
        }
        inputStream =
             new BufferedInputStream(sslSocket.getInputStream(),
                                     DEFAULT_INPUT_BUFFER_SIZE);
        asn1StreamReader = new ASN1StreamReader(inputStream,
             connection.getConnectionOptions().getMaxMessageSize());
        startTLSOutputStream = sslSocket.getOutputStream();
        socket = sslSocket;
        final OutputStream outputStream = startTLSOutputStream;
        startTLSOutputStream = null;
        return outputStream;
      }
      catch (Exception e)
      {
        debugException(e);
        connection.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM,
             getExceptionMessage(e), e);
        startTLSException = e;
        closeRequested = true;
        closeInternal(true, getExceptionMessage(e));
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONNREADER_STARTTLS_FAILED.get(getExceptionMessage(e)), e);
      }
    }
    else
    {
      this.sslContext = sslContext;

      while (true)
      {
        if (startTLSOutputStream != null)
        {
          final OutputStream outputStream = startTLSOutputStream;
          startTLSOutputStream = null;
          return outputStream;
        }
        else if (thread == null)
        {
          if (startTLSException == null)
          {
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_CONNREADER_STARTTLS_FAILED_NO_EXCEPTION.get());
          }
          else
          {
            final Exception e = startTLSException;
            startTLSException = null;

            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_CONNREADER_STARTTLS_FAILED.get(getExceptionMessage(e)), e);
          }
        }

        startTLSSleeper.sleep(10);
      }
    }
  }



   void close(final boolean notifyConnection)
   {
     closeRequested = true;

     for (int i=0; i < 5; i++)
     {
       try
       {
         final Thread t = thread;
         if ((t == null) || (t == Thread.currentThread()) || (! t.isAlive()))
         {
           break;
         }
         else
         {
           t.interrupt();
           t.join(100L);
         }
       }
       catch (Exception e)
       {
         debugException(e);
       }
     }

     closeInternal(notifyConnection, null);
   }



   private void closeInternal(final boolean notifyConnection,
                              final String message)
   {
     final InputStream is = inputStream;
     inputStream = null;

     try
     {
       if (is != null)
       {
         is.close();
       }
     }
     catch (Exception e)
     {
       debugException(e);
     }

     if (notifyConnection)
     {
       connection.setClosed();
     }

     final Iterator<Integer> iterator = acceptorMap.keySet().iterator();
     while (iterator.hasNext())
     {
       final int messageID = iterator.next();
       final ResponseAcceptor acceptor = acceptorMap.get(messageID);

       try
       {
         if (message == null)
         {
           final DisconnectType disconnectType = connection.getDisconnectType();
           if (disconnectType == null)
           {
             acceptor.responseReceived(new ConnectionClosedResponse(
                  ResultCode.SERVER_DOWN, null));
           }
           else
           {
             acceptor.responseReceived(new ConnectionClosedResponse(
                  disconnectType.getResultCode(),
                  connection.getDisconnectMessage()));
           }
         }
         else
         {
           acceptor.responseReceived(new ConnectionClosedResponse(
                ResultCode.SERVER_DOWN, message));
         }
       }
       catch (Exception e)
       {
         debugException(e);
       }

       iterator.remove();
     }
   }



  Thread getReaderThread()
  {
    return thread;
  }



  void updateThreadName()
  {
    final Thread t = thread;
    if (t != null)
    {
      try
      {
        t.setName(constructThreadName(connection.getConnectionInternals(true)));
      }
      catch (final Exception e)
      {
        debugException(e);
      }
    }
  }



  private String constructThreadName(
                      final LDAPConnectionInternals connectionInternals)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("Connection reader for connection ");
    buffer.append(connection.getConnectionID());
    buffer.append(' ');

    String name = connection.getConnectionName();
    if (name != null)
    {
      buffer.append('\'');
      buffer.append(name);
      buffer.append("' ");
    }

    name = connection.getConnectionPoolName();
    if (name != null)
    {
      buffer.append("in pool '");
      buffer.append(name);
      buffer.append("' ");
    }

    if (connectionInternals == null)
    {
      buffer.append("(not connected)");
    }
    else
    {
      buffer.append("to ");
      buffer.append(connectionInternals.getHost());
      buffer.append(':');
      buffer.append(connectionInternals.getPort());
    }

    return buffer.toString();
  }
}
