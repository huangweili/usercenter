package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.ProtocolOp;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class ExtendedRequest
       extends LDAPRequest
       implements ResponseAcceptor, ProtocolOp
{
  protected static final byte TYPE_EXTENDED_REQUEST_OID = (byte) 0x80;



  protected static final byte TYPE_EXTENDED_REQUEST_VALUE = (byte) 0x81;



  private static final long serialVersionUID = 5572410770060685796L;



  private final ASN1OctetString value;

  private int messageID = -1;

  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();


  private final String oid;



  public ExtendedRequest(final String oid)
  {
    super(null);

    ensureNotNull(oid);

    this.oid = oid;

    value = null;
  }


  public ExtendedRequest(final String oid, final Control[] controls)
  {
    super(controls);

    ensureNotNull(oid);

    this.oid = oid;

    value = null;
  }



  public ExtendedRequest(final String oid, final ASN1OctetString value)
  {
    super(null);

    ensureNotNull(oid);

    this.oid   = oid;
    this.value = value;
  }




  public ExtendedRequest(final String oid, final ASN1OctetString value,
                         final Control[] controls)
  {
    super(controls);

    ensureNotNull(oid);

    this.oid   = oid;
    this.value = value;
  }


  protected ExtendedRequest(final ExtendedRequest extendedRequest)
  {
    super(extendedRequest.getControls());

    oid   = extendedRequest.oid;
    value = extendedRequest.value;
  }



  public final String getOID()
  {
    return oid;
  }



  public final boolean hasValue()
  {
    return (value != null);
  }


  public final ASN1OctetString getValue()
  {
    return value;
  }



  public final byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST;
  }


  public final void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);
    writer.addOctetString(TYPE_EXTENDED_REQUEST_OID, oid);

    if (value != null)
    {
      writer.addOctetString(TYPE_EXTENDED_REQUEST_VALUE, value.getValue());
    }
    requestSequence.end();
  }



  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] protocolOpElements;
    if (value == null)
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_OID, oid)
      };
    }
    else
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_OID, oid),
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_VALUE, value.getValue())
      };
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
                            protocolOpElements);
  }



  @Override()
  protected ExtendedResult process(final LDAPConnection connection,
                                   final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection);
    }

    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    connection.registerResponseAcceptor(messageID, this);


    try
    {
      debugLDAPRequest(this);
      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumExtendedRequests();
      connection.sendMessage(message);
      final LDAPResponse response;
      try
      {
        final long responseTimeout = getResponseTimeoutMillis(connection);
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
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
             ERR_EXTOP_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  private ExtendedResult processSync(final LDAPConnection connection)
          throws LDAPException
  {
     messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    try
    {
      connection.getConnectionInternals(true).getSocket().setSoTimeout(
           (int) getResponseTimeoutMillis(connection));
    }
    catch (Exception e)
    {
      debugException(e);
    }

    final long requestTime = System.nanoTime();
    debugLDAPRequest(this);
    connection.getConnectionStatistics().incrementNumExtendedRequests();
    connection.sendMessage(message);

    while (true)
    {
      final LDAPResponse response;
      try
      {
        response = connection.readResponse(messageID);
      }
      catch (final LDAPException le)
      {
        debugException(le);

        if ((le.getResultCode() == ResultCode.TIMEOUT) &&
            connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        throw le;
      }

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



  private ExtendedResult handleResponse(final LDAPConnection connection,
                                        final LDAPResponse response,
                                        final long requestTime)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
      if (connection.getConnectionOptions().abandonOnTimeout())
      {
        connection.abandon(messageID);
      }

      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_EXTENDED_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String msg = ccr.getMessage();
      if (msg == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_EXTENDED_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_EXTENDED_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), msg));
      }
    }

    connection.getConnectionStatistics().incrementNumExtendedResponses(
         System.nanoTime() - requestTime);
    return (ExtendedResult) response;
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


  @Override()
  public final int getLastMessageID()
  {
    return messageID;
  }



  @Override()
  public final OperationType getOperationType()
  {
    return OperationType.EXTENDED;
  }

  public ExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  public ExtendedRequest duplicate(final Control[] controls)
  {
    final ExtendedRequest r = new ExtendedRequest(oid, value, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }


  public String getExtendedRequestName()
  {
    return oid;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ExtendedRequest(oid='");
    buffer.append(oid);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
