package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.protocol.BindRequestProtocolOp;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class SASLBindRequest
       extends BindRequest
       implements ResponseAcceptor
{

  protected static final byte CRED_TYPE_SASL = (byte) 0xA3;


  private static final long serialVersionUID = -5842126553864908312L;


  private int messageID;

  private final LinkedBlockingQueue<LDAPResponse> responseQueue;

  protected SASLBindRequest(final Control[] controls)
  {
    super(controls);

    messageID     = -1;
    responseQueue = new LinkedBlockingQueue<LDAPResponse>();
  }


  @Override()
  public String getBindType()
  {
    return getSASLMechanismName();
  }


  public abstract String getSASLMechanismName();


  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }


  protected final BindResult sendBindRequest(final LDAPConnection connection,
                                  final String bindDN,
                                  final ASN1OctetString saslCredentials,
                                  final Control[] controls,
                                  final long timeoutMillis)
            throws LDAPException
  {
    if (messageID == -1)
    {
      messageID = connection.nextMessageID();
    }

    final BindRequestProtocolOp protocolOp =
         new BindRequestProtocolOp(bindDN, getSASLMechanismName(),
                                   saslCredentials);

    final LDAPMessage requestMessage =
         new LDAPMessage(messageID, protocolOp, controls);
    return sendMessage(connection, requestMessage, timeoutMillis);
  }



  protected final BindResult sendMessage(final LDAPConnection connection,
                                         final LDAPMessage requestMessage,
                                         final long timeoutMillis)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return sendMessageSync(connection, requestMessage, timeoutMillis);
    }

    final int msgID = requestMessage.getMessageID();
    connection.registerResponseAcceptor(msgID, this);
    try
    {
      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumBindRequests();
      connection.sendMessage(requestMessage);

      final LDAPResponse response;
      try
      {
        if (timeoutMillis > 0)
        {
          response = responseQueue.poll(timeoutMillis, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime);
    }
    finally
    {
      connection.deregisterResponseAcceptor(msgID);
    }
  }



  private BindResult sendMessageSync(final LDAPConnection connection,
                                     final LDAPMessage requestMessage,
                                     final long timeoutMillis)
            throws LDAPException
  {

    try
    {
      connection.getConnectionInternals(true).getSocket().setSoTimeout(
           (int) timeoutMillis);
    }
    catch (Exception e)
    {
      debugException(e);
    }


    final int msgID = requestMessage.getMessageID();
    final long requestTime = System.nanoTime();
    connection.getConnectionStatistics().incrementNumBindRequests();
    connection.sendMessage(requestMessage);

    while (true)
    {
      final LDAPResponse response = connection.readResponse(messageID);
      if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else
      {
        return handleResponse(connection, response, requestTime);
      }
    }
  }



  private BindResult handleResponse(final LDAPConnection connection,
                                    final LDAPResponse response,
                                    final long requestTime)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_BIND_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    connection.getConnectionStatistics().incrementNumBindResponses(
         System.nanoTime() - requestTime);
    return (BindResult) response;
  }


  @InternalUseOnly()
  public final void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(getExceptionMessage(e)), e);
    }
  }
}
