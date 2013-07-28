package com.hwlcn.ldap.ldap.sdk;



import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.ProtocolOp;
import com.hwlcn.ldap.ldif.LDIFModifyDNChangeRecord;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 modify DN
 * operation, which can be used to rename and/or move an entry or subtree in the
 * directory.  A modify DN request contains the DN of the target entry, the new
 * RDN to use for that entry, and a flag which indicates whether to remove the
 * current RDN attribute value(s) from the entry.  It may optionally contain a
 * new superior DN, which will cause the entry to be moved below that new parent
 * entry.
 * <BR><BR>
 * Note that some directory servers may not support all possible uses of the
 * modify DN operation.  In particular, some servers may not support the use of
 * a new superior DN, especially if it may cause the entry to be moved to a
 * different database or another server.  Also, some servers may not support
 * renaming or moving non-leaf entries (i.e., entries that have one or more
 * subordinates).
 * <BR><BR>
 * {@code ModifyDNRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code ModifyDNRequest}
 * objects are not threadsafe and therefore a single {@code ModifyDNRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a modify DN
 * operation.  In this case, it will rename "ou=People,dc=example,dc=com" to
 * "ou=Users,dc=example,dc=com".  It will not move the entry below a new parent.
 * <PRE>
 *   ModifyDNRequest modifyDNRequest =
 *        new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
 *
 *   try
 *   {
 *     LDAPResult modifyDNResult = connection.modifyDN(modifyDNRequest);
 *
 *     System.out.println("The entry was renamed successfully.");
 *   }
 *   catch (LDAPException le)
 *   {
 *     System.err.println("The modify DN operation failed.");
 *   }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModifyDNRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyModifyDNRequest, ResponseAcceptor, ProtocolOp
{

  private static final byte NEW_SUPERIOR_TYPE = (byte) 0x80;

  private static final long serialVersionUID = -2325552729975091008L;

  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  private boolean deleteOldRDN;

  private int messageID = -1;

  private String dn;


  private String newRDN;


  private String newSuperiorDN;


  public ModifyDNRequest(final String dn, final String newRDN,
                         final boolean deleteOldRDN)
  {
    super(null);

    ensureNotNull(dn, newRDN);

    this.dn           = dn;
    this.newRDN       = newRDN;
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }


  public ModifyDNRequest(final DN dn, final RDN newRDN,
                         final boolean deleteOldRDN)
  {
    super(null);

    ensureNotNull(dn, newRDN);

    this.dn           = dn.toString();
    this.newRDN       = newRDN.toString();
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }



  public ModifyDNRequest(final String dn, final String newRDN,
                         final boolean deleteOldRDN, final String newSuperiorDN)
  {
    super(null);

    ensureNotNull(dn, newRDN);

    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }


  public ModifyDNRequest(final DN dn, final RDN newRDN,
                         final boolean deleteOldRDN, final DN newSuperiorDN)
  {
    super(null);

    ensureNotNull(dn, newRDN);

    this.dn            = dn.toString();
    this.newRDN        = newRDN.toString();
    this.deleteOldRDN  = deleteOldRDN;

    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
  }


  public ModifyDNRequest(final String dn, final String newRDN,
                         final boolean deleteOldRDN, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, newRDN);

    this.dn           = dn;
    this.newRDN       = newRDN;
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }


  public ModifyDNRequest(final DN dn, final RDN newRDN,
                         final boolean deleteOldRDN, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, newRDN);

    this.dn           = dn.toString();
    this.newRDN       = newRDN.toString();
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }


  public ModifyDNRequest(final String dn, final String newRDN,
                         final boolean deleteOldRDN, final String newSuperiorDN,
                         final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, newRDN);

    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }


  public ModifyDNRequest(final DN dn, final RDN newRDN,
                         final boolean deleteOldRDN, final DN newSuperiorDN,
                         final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, newRDN);

    this.dn            = dn.toString();
    this.newRDN        = newRDN.toString();
    this.deleteOldRDN  = deleteOldRDN;

    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
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


  public String getNewRDN()
  {
    return newRDN;
  }


  public void setNewRDN(final String newRDN)
  {
    ensureNotNull(newRDN);

    this.newRDN = newRDN;
  }


  public void setNewRDN(final RDN newRDN)
  {
    ensureNotNull(newRDN);

    this.newRDN = newRDN.toString();
  }

  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  public void setDeleteOldRDN(final boolean deleteOldRDN)
  {
    this.deleteOldRDN = deleteOldRDN;
  }


  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }

  public void setNewSuperiorDN(final String newSuperiorDN)
  {
    this.newSuperiorDN = newSuperiorDN;
  }

  public void setNewSuperiorDN(final DN newSuperiorDN)
  {
    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
  }

  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST;
  }

  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);
    writer.addOctetString(dn);
    writer.addOctetString(newRDN);
    writer.addBoolean(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      writer.addOctetString(NEW_SUPERIOR_TYPE, newSuperiorDN);
    }
    requestSequence.end();
  }

  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] protocolOpElements;
    if (newSuperiorDN == null)
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(dn),
        new ASN1OctetString(newRDN),
        new ASN1Boolean(deleteOldRDN)
      };
    }
    else
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(dn),
        new ASN1OctetString(newRDN),
        new ASN1Boolean(deleteOldRDN),
        new ASN1OctetString(NEW_SUPERIOR_TYPE, newSuperiorDN)
      };
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
                            protocolOpElements);
  }

  @Override()
  protected LDAPResult process(final LDAPConnection connection, final int depth)
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
             ERR_MODDN_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }


  AsyncRequestID processAsync(final LDAPConnection connection,
                              final AsyncResultListener resultListener)
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
      final AsyncHelper helper = new AsyncHelper(connection,
           OperationType.MODIFY_DN, messageID, resultListener,
           getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, helper);
      asyncRequestID = helper.getAsyncRequestID();

      final long timeout = getResponseTimeoutMillis(connection);
      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(helper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }
    try
    {
      debugLDAPRequest(this);
      connection.getConnectionStatistics().incrementNumModifyDNRequests();
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


  private LDAPResult processSync(final LDAPConnection connection,
                                 final int depth,
                                 final boolean allowRetry)
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
    connection.getConnectionStatistics().incrementNumModifyDNRequests();
    try
    {
      connection.sendMessage(message);
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
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
          final LDAPResult retryResult = reconnectAndRetry(connection, depth,
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


  private LDAPResult handleResponse(final LDAPConnection connection,
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
           ERR_MODIFY_DN_CLIENT_TIMEOUT.get(waitTime,
                connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumModifyDNResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
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
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_DN_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_DN_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final LDAPResult result = (LDAPResult) response;
    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >= connection.getConnectionOptions().getReferralHopLimit())
      {
        return new LDAPResult(messageID, ResultCode.REFERRAL_LIMIT_EXCEEDED,
                              ERR_TOO_MANY_REFERRALS.get(),
                              result.getMatchedDN(), result.getReferralURLs(),
                              result.getResponseControls());
      }

      return followReferral(result, connection, depth);
    }
    else
    {
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             result.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      return result;
    }
  }


 private LDAPResult reconnectAndRetry(final LDAPConnection connection,
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


  private LDAPResult followReferral(final LDAPResult referralResult,
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

        final ModifyDNRequest modifyDNRequest;
        if (referralURL.baseDNProvided())
        {
          modifyDNRequest =
               new ModifyDNRequest(referralURL.getBaseDN().toString(),
                                   newRDN, deleteOldRDN, newSuperiorDN,
                                   getControls());
        }
        else
        {
          modifyDNRequest = this;
        }

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return modifyDNRequest.process(referralConn, depth+1);
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
    return OperationType.MODIFY_DN;
  }


  public ModifyDNRequest duplicate()
  {
    return duplicate(getControls());
  }


  public ModifyDNRequest duplicate(final Control[] controls)
  {
    final ModifyDNRequest r = new ModifyDNRequest(dn, newRDN, deleteOldRDN,
         newSuperiorDN, controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }


  public LDIFModifyDNChangeRecord toLDIFChangeRecord()
  {
    return new LDIFModifyDNChangeRecord(this);
  }


  public String[] toLDIF()
  {
    return toLDIFChangeRecord().toLDIF();
  }

  public String toLDIFString()
  {
    return toLDIFChangeRecord().toLDIFString();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ModifyDNRequest(dn='");
    buffer.append(dn);
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

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
