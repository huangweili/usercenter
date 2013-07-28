package com.hwlcn.ldap.ldap.sdk;



import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.ProtocolOp;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.ldap.util.LDAPSDKUsageException;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SimpleBindRequest
       extends BindRequest
       implements ResponseAcceptor, ProtocolOp
{

  private static final byte CRED_TYPE_SIMPLE = (byte) 0x80;



  private static final ASN1OctetString NO_BIND_DN = new ASN1OctetString();



  private static final ASN1OctetString NO_PASSWORD =
       new ASN1OctetString(CRED_TYPE_SIMPLE);

  private static final long serialVersionUID = 4725871243149974407L;


  private int messageID = -1;

  private final ASN1OctetString bindDN;

  private final ASN1OctetString password;

  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  private final PasswordProvider passwordProvider;


  public SimpleBindRequest()
  {
    this(NO_BIND_DN, NO_PASSWORD, null, NO_CONTROLS);
  }




  public SimpleBindRequest(final String bindDN, final String password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  public SimpleBindRequest(final String bindDN, final byte[] password)
  {
    this(bindDN, password, NO_CONTROLS);
  }


  public SimpleBindRequest(final DN bindDN, final String password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  public SimpleBindRequest(final DN bindDN, final byte[] password)
  {
    this(bindDN, password, NO_CONTROLS);
  }


  public SimpleBindRequest(final String bindDN, final String password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN);
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    passwordProvider = null;
  }


  public SimpleBindRequest(final String bindDN, final byte[] password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN);
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    passwordProvider = null;
  }


  public SimpleBindRequest(final DN bindDN, final String password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN.toString());
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    passwordProvider = null;
  }


  public SimpleBindRequest(final DN bindDN, final byte[] password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN.toString());
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    passwordProvider = null;
  }


  public SimpleBindRequest(final String bindDN,
                           final PasswordProvider passwordProvider,
                           final Control... controls)
  {
    super(controls);

    this.bindDN           = new ASN1OctetString(bindDN);
    this.passwordProvider = passwordProvider;

    password = null;
  }



  public SimpleBindRequest(final DN bindDN,
                           final PasswordProvider passwordProvider,
                           final Control... controls)
  {
    super(controls);

    this.bindDN           = new ASN1OctetString(bindDN.toString());
    this.passwordProvider = passwordProvider;

    password = null;
  }


  private SimpleBindRequest(final ASN1OctetString bindDN,
                            final ASN1OctetString password,
                            final PasswordProvider passwordProvider,
                            final Control... controls)
  {
    super(controls);

    this.bindDN           = bindDN;
    this.password         = password;
    this.passwordProvider = passwordProvider;
  }

  public String getBindDN()
  {
    return bindDN.stringValue();
  }


  public ASN1OctetString getPassword()
  {
    return password;
  }

  public PasswordProvider getPasswordProvider()
  {
    return passwordProvider;
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
    buffer.addElement(VERSION_ELEMENT);
    buffer.addElement(bindDN);

    if (passwordProvider == null)
    {
      buffer.addElement(password);
    }
    else
    {
      byte[] pwBytes;
      try
      {
        pwBytes = passwordProvider.getPasswordBytes();
      }
      catch (final LDAPException le)
      {
        debugException(le);
        throw new LDAPRuntimeException(le);
      }

      final ASN1OctetString pw = new ASN1OctetString(CRED_TYPE_SIMPLE, pwBytes);
      buffer.addElement(pw);
      buffer.setZeroBufferOnClear();
      Arrays.fill(pwBytes, (byte) 0x00);
    }

    requestSequence.end();
  }



  public ASN1Element encodeProtocolOp()
         throws LDAPSDKUsageException
  {
    if (password == null)
    {
      throw new LDAPSDKUsageException(
           ERR_SIMPLE_BIND_ENCODE_PROTOCOL_OP_WITH_PROVIDER.get());
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
         new ASN1Integer(3),
         bindDN,
         password);
  }


  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection,
           connection.getConnectionOptions().autoReconnect());
    }

    if (password != null)
    {
      if ((bindDN.getValue().length > 0) && (password.getValue().length == 0) &&
           connection.getConnectionOptions().bindWithDNRequiresPassword())
      {
        final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SIMPLE_BIND_DN_WITHOUT_PASSWORD.get());
        debugCodingError(le);
        throw le;
      }
    }


    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());

    connection.registerResponseAcceptor(messageID, this);


    try
    {
      debugLDAPRequest(this);
      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumBindRequests();
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
             ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  private BindResult processSync(final LDAPConnection connection,
                                 final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID, this, getControls());

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
    connection.getConnectionStatistics().incrementNumBindRequests();
    try
    {
      connection.sendMessage(message);
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (allowRetry)
      {
        final BindResult bindResult = reconnectAndRetry(connection,
             le.getResultCode());
        if (bindResult != null)
        {
          return bindResult;
        }
      }
    }

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
        return handleResponse(connection, response, requestTime, allowRetry);
      }
    }
  }



  private BindResult handleResponse(final LDAPConnection connection,
                                    final LDAPResponse response,
                                    final long requestTime,
                                    final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_BIND_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumBindResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      if (allowRetry)
      {
        final BindResult retryResult = reconnectAndRetry(connection,
             ResultCode.SERVER_DOWN);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

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

    final BindResult bindResult = (BindResult) response;
    if (allowRetry)
    {
      final BindResult retryResult = reconnectAndRetry(connection,
           bindResult.getResultCode());
      if (retryResult != null)
      {
        return retryResult;
      }
    }

    return bindResult;
  }


  private BindResult reconnectAndRetry(final LDAPConnection connection,
                                       final ResultCode resultCode)
  {
    try
    {

      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          connection.reconnect();
          return processSync(connection, false);
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    return null;
  }



  @Override()
  public SimpleBindRequest getRebindRequest(final String host, final int port)
  {
    return new SimpleBindRequest(bindDN, password, passwordProvider,
         getControls());
  }


  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
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
  public String getBindType()
  {
    return "SIMPLE";
  }



  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }

  @Override()
  public SimpleBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  @Override()
  public SimpleBindRequest duplicate(final Control[] controls)
  {
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(bindDN, password, passwordProvider, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SimpleBindRequest(dn='");
    buffer.append(bindDN);
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
