package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.ProtocolOp;
import com.hwlcn.ldap.ldif.LDIFAddChangeRecord;
import com.hwlcn.ldap.ldif.LDIFException;
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
 * This class implements the processing necessary to perform an LDAPv3 add
 * operation, which creates a new entry in the directory.  An add request
 * contains the DN for the entry and the set of attributes to include.  It may
 * also include a set of controls to send to the server.
 * <BR><BR>
 * The contents of the entry to may be specified as a separate DN and collection
 * of attributes, as an {@link com.hwlcn.ldap.ldap.sdk.Entry} object, or as a list of the lines that
 * comprise the LDIF representation of the entry to add as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.  For example, the
 * following code demonstrates creating an add request from the LDIF
 * representation of the entry:
 * <PRE>
 *   AddRequest addRequest = new AddRequest(
 *     "dn: dc=example,dc=com",
 *     "objectClass: top",
 *     "objectClass: domain",
 *     "dc: example");
 * </PRE>
 * <BR><BR>
 * {@code AddRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code AddRequest}
 * objects are not threadsafe and therefore a single {@code AddRequest} object
 * instance should not be used to process multiple requests at the same time.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class AddRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyAddRequest, ResponseAcceptor, ProtocolOp
{

  private static final long serialVersionUID = 1320730292848237219L;

  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  private ArrayList<Attribute> attributes;

  private int messageID = -1;

  private String dn;

  public AddRequest(final String dn, final Attribute... attributes)
  {
    super(null);

    ensureNotNull(dn, attributes);

    this.dn = dn;

    this.attributes = new ArrayList<Attribute>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  public AddRequest(final String dn, final Attribute[] attributes,
                    final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributes);

    this.dn = dn;

    this.attributes = new ArrayList<Attribute>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  public AddRequest(final String dn, final Collection<Attribute> attributes)
  {
    super(null);

    ensureNotNull(dn, attributes);

    this.dn         = dn;
    this.attributes = new ArrayList<Attribute>(attributes);
  }



  public AddRequest(final String dn, final Collection<Attribute> attributes,
                    final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributes);

    this.dn         = dn;
    this.attributes = new ArrayList<Attribute>(attributes);
  }



  public AddRequest(final DN dn, final Attribute... attributes)
  {
    super(null);

    ensureNotNull(dn, attributes);

    this.dn = dn.toString();

    this.attributes = new ArrayList<Attribute>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }


  public AddRequest(final DN dn, final Attribute[] attributes,
                    final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributes);

    this.dn = dn.toString();

    this.attributes = new ArrayList<Attribute>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }


  public AddRequest(final DN dn, final Collection<Attribute> attributes)
  {
    super(null);

    ensureNotNull(dn, attributes);

    this.dn         = dn.toString();
    this.attributes = new ArrayList<Attribute>(attributes);
  }


  public AddRequest(final DN dn, final Collection<Attribute> attributes,
                    final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributes);

    this.dn         = dn.toString();
    this.attributes = new ArrayList<Attribute>(attributes);
  }



  public AddRequest(final Entry entry)
  {
    super(null);

    ensureNotNull(entry);

    dn         = entry.getDN();
    attributes = new ArrayList<Attribute>(entry.getAttributes());
  }



  public AddRequest(final Entry entry, final Control[] controls)
  {
    super(controls);

    ensureNotNull(entry);

    dn         = entry.getDN();
    attributes = new ArrayList<Attribute>(entry.getAttributes());
  }


  public AddRequest(final String... ldifLines)
         throws LDIFException
  {
    this(LDIFReader.decodeEntry(ldifLines));
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




  public List<Attribute> getAttributes()
  {
    return Collections.unmodifiableList(attributes);
  }



  public Attribute getAttribute(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final Attribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a;
      }
    }

    return null;
  }




  public boolean hasAttribute(final String attributeName)
  {
    return (getAttribute(attributeName) != null);
  }



  public boolean hasAttribute(final Attribute attribute)
  {
    ensureNotNull(attribute);

    final Attribute a = getAttribute(attribute.getName());
    return ((a != null) && attribute.equals(a));
  }



  public boolean hasAttributeValue(final String attributeName,
                                   final String attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue));
  }


  public boolean hasAttributeValue(final String attributeName,
                                   final String attributeValue,
                                   final MatchingRule matchingRule)
  {
    ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue, matchingRule));
  }


  public boolean hasAttributeValue(final String attributeName,
                                   final byte[] attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue));
  }



  public boolean hasAttributeValue(final String attributeName,
                                   final byte[] attributeValue,
                                   final MatchingRule matchingRule)
  {
    ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue, matchingRule));
  }




  public boolean hasObjectClass(final String objectClassName)
  {
    return hasAttributeValue("objectClass", objectClassName);
  }


  public Entry toEntry()
  {
    return new Entry(dn, attributes);
  }



  public void setAttributes(final Attribute[] attributes)
  {
    ensureNotNull(attributes);

    this.attributes.clear();
    this.attributes.addAll(Arrays.asList(attributes));
  }

  public void setAttributes(final Collection<Attribute> attributes)
  {
    ensureNotNull(attributes);

    this.attributes.clear();
    this.attributes.addAll(attributes);
  }

  public void addAttribute(final Attribute attribute)
  {
    ensureNotNull(attribute);

    for (int i=0 ; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(attribute.getName()))
      {
        attributes.set(i, Attribute.mergeAttributes(a, attribute));
        return;
      }
    }

    attributes.add(attribute);
  }

  public void addAttribute(final String name, final String value)
  {
    ensureNotNull(name, value);
    addAttribute(new Attribute(name, value));
  }

  public void addAttribute(final String name, final byte[] value)
  {
    ensureNotNull(name, value);
    addAttribute(new Attribute(name, value));
  }

  public void addAttribute(final String name, final String... values)
  {
    ensureNotNull(name, values);
    addAttribute(new Attribute(name, values));
  }

  public void addAttribute(final String name, final byte[]... values)
  {
    ensureNotNull(name, values);
    addAttribute(new Attribute(name, values));
  }


  public boolean removeAttribute(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Iterator<Attribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      final Attribute a = iterator.next();
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        iterator.remove();
        return true;
      }
    }

    return false;
  }


  public boolean removeAttributeValue(final String name, final String value)
  {
    ensureNotNull(name, value);

    int pos = -1;
    for (int i=0; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(name))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    final Attribute a = attributes.get(pos);
    final Attribute newAttr =
         Attribute.removeValues(a, new Attribute(name, value));

    if (a.getRawValues().length == newAttr.getRawValues().length)
    {
      return false;
    }

    if (newAttr.getRawValues().length == 0)
    {
      attributes.remove(pos);
    }
    else
    {
      attributes.set(pos, newAttr);
    }

    return true;
  }

  public boolean removeAttribute(final String name, final byte[] value)
  {
    ensureNotNull(name, value);

    int pos = -1;
    for (int i=0; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(name))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    final Attribute a = attributes.get(pos);
    final Attribute newAttr =
         Attribute.removeValues(a, new Attribute(name, value));

    if (a.getRawValues().length == newAttr.getRawValues().length)
    {
      return false;
    }

    if (newAttr.getRawValues().length == 0)
    {
      attributes.remove(pos);
    }
    else
    {
      attributes.set(pos, newAttr);
    }

    return true;
  }

  public void replaceAttribute(final Attribute attribute)
  {
    ensureNotNull(attribute);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(attribute.getName()))
      {
        attributes.set(i, attribute);
        return;
      }
    }

    attributes.add(attribute);
  }

  public void replaceAttribute(final String name, final String value)
  {
    ensureNotNull(name, value);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, value));
        return;
      }
    }

    attributes.add(new Attribute(name, value));
  }

  public void replaceAttribute(final String name, final byte[] value)
  {
    ensureNotNull(name, value);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, value));
        return;
      }
    }

    attributes.add(new Attribute(name, value));
  }

  public void replaceAttribute(final String name, final String... values)
  {
    ensureNotNull(name, values);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, values));
        return;
      }
    }

    attributes.add(new Attribute(name, values));
  }

  public void replaceAttribute(final String name, final byte[]... values)
  {
    ensureNotNull(name, values);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, values));
        return;
      }
    }

    attributes.add(new Attribute(name, values));
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final Attribute a : attributes)
    {
      a.writeTo(buffer);
    }
    attrSequence.end();

    requestSequence.end();
  }


  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] attrElements = new ASN1Element[attributes.size()];
    for (int i=0; i < attrElements.length; i++)
    {
      attrElements[i] = attributes.get(i).encode();
    }

    final ASN1Element[] addRequestElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(attrElements)
    };

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
                            addRequestElements);
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
             ERR_ADD_INTERRUPTED.get(connection.getHostPort()), ie);
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
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());
    final AsyncRequestID asyncRequestID;
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncHelper helper = new AsyncHelper(connection, OperationType.ADD,
           messageID, resultListener, getIntermediateResponseListener());
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
      connection.getConnectionStatistics().incrementNumAddRequests();
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
    connection.getConnectionStatistics().incrementNumAddRequests();
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
           ERR_ADD_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumAddResponses(
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
             ERR_CONN_CLOSED_WAITING_FOR_ADD_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ADD_RESPONSE_WITH_MESSAGE.get(
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

        final AddRequest addRequest;
        if (referralURL.baseDNProvided())
        {
          addRequest = new AddRequest(referralURL.getBaseDN(), attributes,
                                      getControls());
        }
        else
        {
          addRequest = this;
        }

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return addRequest.process(referralConn, (depth+1));
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

  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }


  @Override()
  public OperationType getOperationType()
  {
    return OperationType.ADD;
  }


  public AddRequest duplicate()
  {
    return duplicate(getControls());
  }


  public AddRequest duplicate(final Control[] controls)
  {
    final ArrayList<Attribute> attrs = new ArrayList<Attribute>(attributes);
    final AddRequest r = new AddRequest(dn, attrs, controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
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


  public LDIFAddChangeRecord toLDIFChangeRecord()
  {
    return new LDIFAddChangeRecord(this);
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
    buffer.append("AddRequest(dn='");
    buffer.append(dn);
    buffer.append("', attrs={");

    for (int i=0; i < attributes.size(); i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(attributes.get(i));
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
