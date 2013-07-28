package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
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
import com.hwlcn.ldap.ldif.LDIFChangeRecord;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.ldap.ldif.LDIFModifyChangeRecord;
import com.hwlcn.ldap.ldif.LDIFReader;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 modify
 * operation, which can be used to update an entry in the directory server.  A
 * modify request contains the DN of the entry to modify, as well as one or more
 * changes to apply to that entry.  See the {@link com.hwlcn.ldap.ldap.sdk.Modification} class for more
 * information about the types of modifications that may be processed.
 * <BR><BR>
 * A modify request can be created with a DN and set of modifications, but it
 * can also be as a list of the lines that comprise the LDIF representation of
 * the modification as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.  For example, the
 * following code demonstrates creating a modify request from the LDIF
 * representation of the modification:
 * <PRE>
 *   ModifyRequest modifyRequest = new ModifyRequest(
 *     "dn: dc=example,dc=com",
 *     "changetype: modify",
 *     "replace: description",
 *     "description: This is the new description.");
 * </PRE>
 * <BR><BR>
 * {@code ModifyRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code ModifyRequest}
 * objects are not threadsafe and therefore a single {@code ModifyRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModifyRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyModifyRequest, ResponseAcceptor, ProtocolOp
{

  private static final long serialVersionUID = -4747622844001634758L;



  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  private final ArrayList<Modification> modifications;

  private int messageID = -1;

  private String dn;




  public ModifyRequest(final String dn, final Modification mod)
  {
    super(null);

    ensureNotNull(dn, mod);

    this.dn = dn;

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }




  public ModifyRequest(final String dn, final Modification... mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  public ModifyRequest(final String dn, final List<Modification> mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods);
  }



  public ModifyRequest(final DN dn, final Modification mod)
  {
    super(null);

    ensureNotNull(dn, mod);

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  public ModifyRequest(final DN dn, final Modification... mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  public ModifyRequest(final DN dn, final List<Modification> mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods);
  }




  public ModifyRequest(final String dn, final Modification mod,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mod);

    this.dn = dn;

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }




  public ModifyRequest(final String dn, final Modification[] mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  public ModifyRequest(final String dn, final List<Modification> mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods);
  }



  public ModifyRequest(final DN dn, final Modification mod,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mod);

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  public ModifyRequest(final DN dn, final Modification[] mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  public ModifyRequest(final DN dn, final List<Modification> mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods);
  }




  public ModifyRequest(final String... ldifModificationLines)
         throws LDIFException
  {
    super(null);

    final LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(ldifModificationLines);
    if (! (changeRecord instanceof LDIFModifyChangeRecord))
    {
      throw new LDIFException(ERR_MODIFY_INVALID_LDIF.get(), 0, false,
                              ldifModificationLines, null);
    }

    final LDIFModifyChangeRecord modifyRecord =
         (LDIFModifyChangeRecord) changeRecord;
    final ModifyRequest r = modifyRecord.toModifyRequest();

    dn            = r.dn;
    modifications = r.modifications;
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



  public List<Modification> getModifications()
  {
    return Collections.unmodifiableList(modifications);
  }



  public void addModification(final Modification mod)
  {
    ensureNotNull(mod);

    modifications.add(mod);
  }




  public boolean removeModification(final Modification mod)
  {
    ensureNotNull(mod);

    return modifications.remove(mod);
  }


  public void setModifications(final Modification mod)
  {
    ensureNotNull(mod);

    modifications.clear();
    modifications.add(mod);
  }



  public void setModifications(final Modification[] mods)
  {
    ensureNotNull(mods);
    ensureFalse(mods.length == 0,
                "ModifyRequest.setModifications.mods must not be empty.");

    modifications.clear();
    modifications.addAll(Arrays.asList(mods));
  }



  public void setModifications(final List<Modification> mods)
  {
    ensureNotNull(mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.setModifications.mods must not be empty.");

    modifications.clear();
    modifications.addAll(mods);
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST;
  }



  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);
    writer.addOctetString(dn);

    final ASN1BufferSequence modSequence = writer.beginSequence();
    for (final Modification m : modifications)
    {
      m.writeTo(writer);
    }
    modSequence.end();
    requestSequence.end();
  }



  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] modElements = new ASN1Element[modifications.size()];
    for (int i=0; i < modElements.length; i++)
    {
      modElements[i] = modifications.get(i).encode();
    }

    final ASN1Element[] protocolOpElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(modElements)
    };



    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
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
             ERR_MODIFY_INTERRUPTED.get(connection.getHostPort()), ie);
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
           OperationType.MODIFY, messageID, resultListener,
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
      connection.getConnectionStatistics().incrementNumModifyRequests();
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
    connection.getConnectionStatistics().incrementNumModifyRequests();
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
           ERR_MODIFY_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumModifyResponses(
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
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_RESPONSE_WITH_MESSAGE.get(
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

        final ModifyRequest modifyRequest;
        if (referralURL.baseDNProvided())
        {
          modifyRequest = new ModifyRequest(referralURL.getBaseDN(),
                                            modifications, getControls());
        }
        else
        {
          modifyRequest = this;
        }

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return modifyRequest.process(referralConn, depth+1);
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
    return OperationType.MODIFY;
  }



  public ModifyRequest duplicate()
  {
    return duplicate(getControls());
  }



  public ModifyRequest duplicate(final Control[] controls)
  {
    final ModifyRequest r = new ModifyRequest(dn,
         new ArrayList<Modification>(modifications), controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  public LDIFModifyChangeRecord toLDIFChangeRecord()
  {
    return new LDIFModifyChangeRecord(this);
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
    buffer.append("ModifyRequest(dn='");
    buffer.append(dn);
    buffer.append("', mods={");
    for (int i=0; i < modifications.size(); i++)
    {
      final Modification m = modifications.get(i);

      if (i > 0)
      {
        buffer.append(", ");
      }

      switch (m.getModificationType().intValue())
      {
        case 0:
          buffer.append("ADD ");
          break;

        case 1:
          buffer.append("DELETE ");
          break;

        case 2:
          buffer.append("REPLACE ");
          break;

        case 3:
          buffer.append("INCREMENT ");
          break;
      }

      buffer.append(m.getAttributeName());
    }
    buffer.append('}');

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
