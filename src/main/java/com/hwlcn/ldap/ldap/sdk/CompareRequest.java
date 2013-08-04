package com.hwlcn.ldap.ldap.sdk;



import java.util.Timer;
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
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 compare
 * operation, which may be used to determine whether a specified entry contains
 * a given attribute value.  Compare requests include the DN of the target
 * entry, the name of the target attribute, and the value for which to make the
 * determination.  It may also include a set of controls to send to the server.
 * <BR><BR>
 * The assertion value may be specified as either a string or a byte array.  If
 * it is specified as a byte array, then it may represent either a binary or a
 * string value.  If a string value is provided as a byte array, then it should
 * use the UTF-8 encoding for that value.
 * <BR><BR>
 * {@code CompareRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code CompareRequest}
 * objects are not threadsafe and therefore a single {@code CompareRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a compare
 * operation:
 * <PRE>
 *   CompareRequest compareRequest =
 *        new CompareRequest("dc=example,dc=com", "description", "test");
 *
 *   try
 *   {
 *     CompareResult compareResult = connection.compare(compareRequest);
 *
 *     // The compare operation didn't throw an exception, so we can try to
 *     // determine whether the compare matched.
 *     if (compareResult.compareMatched())
 *     {
 *       System.out.println("The entry does have a description value of test");
 *     }
 *     else
 *     {
 *       System.out.println("The entry does not have a description value of " +
 *                          "test");
 *     }
 *   }
 *   catch (LDAPException le)
 *   {
 *     System.err.println("The compare operation failed.");
 *   }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CompareRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyCompareRequest, ResponseAcceptor, ProtocolOp
{
  private static final long serialVersionUID = 6343453776330347024L;



  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  private ASN1OctetString assertionValue;

  private int messageID = -1;

  private String attributeName;

  private String dn;


  public CompareRequest(final String dn, final String attributeName,
                        final String assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public CompareRequest(final String dn, final String attributeName,
                        final byte[] assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public CompareRequest(final DN dn, final String attributeName,
                        final String assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }




  public CompareRequest(final DN dn, final String attributeName,
                        final byte[] assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }




  public CompareRequest(final String dn, final String attributeName,
                        final String assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public CompareRequest(final String dn, final String attributeName,
                        final byte[] assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public CompareRequest(final DN dn, final String attributeName,
                        final String assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public CompareRequest(final DN dn, final String attributeName,
                        final ASN1OctetString assertionValue,
                        final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = assertionValue;
  }



  public CompareRequest(final DN dn, final String attributeName,
                        final byte[] assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  public String getDN()
  {
    return dn;
  }




  public void setDN(final String dn)
  {
    ensureNotNull(dn);

    this.dn = dn;
  }



  public void setDN(final DN dn)
  {
    ensureNotNull(dn);

    this.dn = dn.toString();
  }



  public String getAttributeName()
  {
    return attributeName;
  }




  public void setAttributeName(final String attributeName)
  {
    ensureNotNull(attributeName);

    this.attributeName = attributeName;
  }



  public String getAssertionValue()
  {
    return assertionValue.stringValue();
  }




  public byte[] getAssertionValueBytes()
  {
    return assertionValue.getValue();
  }




  public ASN1OctetString getRawAssertionValue()
  {
    return assertionValue;
  }




  public void setAssertionValue(final String assertionValue)
  {
    ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }




  public void setAssertionValue(final byte[] assertionValue)
  {
    ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }




  public void setAssertionValue(final ASN1OctetString assertionValue)
  {
    this.assertionValue = assertionValue;
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence avaSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);
    buffer.addElement(assertionValue);
    avaSequence.end();
    requestSequence.end();
  }


  public ASN1Element encodeProtocolOp()
  {

    final ASN1Element[] avaElements =
    {
      new ASN1OctetString(attributeName),
      assertionValue
    };

    final ASN1Element[] protocolOpElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(avaElements)
    };

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
                            protocolOpElements);
  }



  @Override()
  protected CompareResult process(final LDAPConnection connection,
                                  final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection, depth,
           connection.getConnectionOptions().autoReconnect());
    }

    final long requestTime = System.nanoTime();
    processAsync(connection, null);

    try
    {
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
             ERR_COMPARE_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response,  requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }




  AsyncRequestID processAsync(final LDAPConnection connection,
                              final AsyncCompareResultListener resultListener)
                 throws LDAPException
  {
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());

    final AsyncRequestID asyncRequestID;
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncCompareHelper compareHelper =
           new AsyncCompareHelper(connection, messageID, resultListener,
                getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, compareHelper);
      asyncRequestID = compareHelper.getAsyncRequestID();

      final long timeout = getResponseTimeoutMillis(connection);
      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(compareHelper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }


    try
    {
      debugLDAPRequest(this);
      connection.getConnectionStatistics().incrementNumCompareRequests();
      connection.sendMessage(message);
      return asyncRequestID;
    }
    catch (LDAPException le)
    {
      debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }




  private CompareResult processSync(final LDAPConnection connection,
                                    final int depth, final boolean allowRetry)
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
    connection.getConnectionStatistics().incrementNumCompareRequests();
    try
    {
      connection.sendMessage(message);
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
             le.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      throw le;
    }

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

        if (allowRetry)
        {
          final CompareResult retryResult = reconnectAndRetry(connection, depth,
               le.getResultCode());
          if (retryResult != null)
          {
            return retryResult;
          }
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
        return handleResponse(connection, response, requestTime, depth,
             allowRetry);
      }
    }
  }




  private CompareResult handleResponse(final LDAPConnection connection,
                                       final LDAPResponse response,
                                       final long requestTime, final int depth,
                                       final boolean allowRetry)
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
           ERR_COMPARE_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumCompareResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
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
             ERR_CONN_CLOSED_WAITING_FOR_COMPARE_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_COMPARE_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final CompareResult result;
    if (response instanceof CompareResult)
    {
      result = (CompareResult) response;
    }
    else
    {
      result = new CompareResult((LDAPResult) response);
    }

    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >= connection.getConnectionOptions().getReferralHopLimit())
      {
        return new CompareResult(messageID,
                                 ResultCode.REFERRAL_LIMIT_EXCEEDED,
                                 ERR_TOO_MANY_REFERRALS.get(),
                                 result.getMatchedDN(),
                                 result.getReferralURLs(),
                                 result.getResponseControls());
      }

      return followReferral(result, connection, depth);
    }
    else
    {
      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
             result.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      return result;
    }
  }

    private CompareResult reconnectAndRetry(final LDAPConnection connection,
                                          final int depth,
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
          return processSync(connection, depth, false);
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    return null;
  }




  private CompareResult followReferral(final CompareResult referralResult,
                                       final LDAPConnection connection,
                                       final int depth)
          throws LDAPException
  {
    for (final String urlString : referralResult.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {
        continue;
        }

        final CompareRequest compareRequest;
        if (referralURL.baseDNProvided())
        {
          compareRequest = new CompareRequest(referralURL.getBaseDN(),
                                              attributeName, assertionValue,
                                              getControls());
        }
        else
        {
          compareRequest = this;
        }

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return compareRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (LDAPException le)
      {
        debugException(le);
      }
    }


    return referralResult;
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
  public int getLastMessageID()
  {
    return messageID;
  }



  @Override()
  public OperationType getOperationType()
  {
    return OperationType.COMPARE;
  }



  public CompareRequest duplicate()
  {
    return duplicate(getControls());
  }



  public CompareRequest duplicate(final Control[] controls)
  {
    final CompareRequest r = new CompareRequest(dn, attributeName,
         assertionValue.getValue(), controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("CompareRequest(dn='");
    buffer.append(dn);
    buffer.append("', attr='");
    buffer.append(attributeName);
    buffer.append("', value='");
    buffer.append(assertionValue.stringValue());
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

