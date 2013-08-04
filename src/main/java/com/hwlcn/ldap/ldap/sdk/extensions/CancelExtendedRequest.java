package com.hwlcn.ldap.ldap.sdk.extensions;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.AsyncRequestID;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



/**
 * This class provides an implementation of the LDAP cancel extended request as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc3909.txt">RFC 3909</A>.  It
 * may be used to request that the server interrupt processing on another
 * operation in progress on the same connection.  It behaves much like the
 * abandon operation, with the exception that both the cancel request and the
 * operation that is canceled will receive responses, whereas an abandon request
 * never returns a response, and the operation that is abandoned will also not
 * receive a response if the abandon is successful.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example initiates an asynchronous modify operation and then
 * attempts to cancel it:
 * <PRE>
 *   Modification mod = new Modification(ModificationType.REPLACE,
 *        "description", "This is the new description.");
 *   ModifyRequest modifyRequest =
 *        new ModifyRequest("dc=example,dc=com", mod);
 *
 *   AsyncRequestID asyncRequestID =
 *        connection.asyncModify(modifyRequest, myAsyncResultListener);
 *
 *   // Assume that we've waited a reasonable amount of time but the modify
 *   // hasn't completed yet so we'll try to cancel it.
 *
 *   CancelExtendedRequest cancelRequest =
 *        new CancelExtendedRequest(asyncRequestID);
 *
 *   // NOTE:  The processExtendedOperation method will only throw an exception
 *   // if a problem occurs while trying to send the request or read the
 *   // response.  It will not throw an exception because of a non-success
 *   // response.  That's good for us in this case because the cancel result
 *   // should never be "SUCCESS".
 *   ExtendedResult cancelResult =
 *        connection.processExtendedOperation(cancelRequest);
 *   switch (cancelResult.getResultCode())
 *   {
 *     case ResultCode.CANCELED:
 *       System.out.println("The operation was successfully canceled.");
 *       break;
 *     case ResultCode.NO_SUCH_OPERATION:
 *       System.out.println("The server didn't know anything about the " +
 *                          "operation.  Maybe it's already completed.");
 *       break;
 *     case ResultCode.TOO_LATE:
 *       System.out.println("It was too late in the operation processing " +
 *                          "to cancel the operation.");
 *       break;
 *     case ResultCode.CANNOT_CANCEL:
 *       System.out.println("The target operation is not one that could be " +
 *                          "canceled.");
 *       break;
 *     default:
 *       System.err.println("An error occurred while processing the cancel " +
 *                          "request.");
 *       break;
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CancelExtendedRequest
       extends ExtendedRequest
{

  public static final String CANCEL_REQUEST_OID = "1.3.6.1.1.8";


  private static final long serialVersionUID = -7170687636394194183L;

  private final int targetMessageID;

  public CancelExtendedRequest(final AsyncRequestID requestID)
  {
    this(requestID.getMessageID(), null);
  }

  public CancelExtendedRequest(final int targetMessageID)
  {
    this(targetMessageID, null);
  }

  public CancelExtendedRequest(final AsyncRequestID requestID,
                               final Control[] controls)
  {
    this(requestID.getMessageID(), controls);
  }


  public CancelExtendedRequest(final int targetMessageID,
                               final Control[] controls)
  {
    super(CANCEL_REQUEST_OID, encodeValue(targetMessageID), controls);

    this.targetMessageID = targetMessageID;
  }

  public CancelExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CANCEL_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      targetMessageID = ASN1Integer.decodeAsInteger(elements[0]).intValue();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CANCEL_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }

  private static ASN1OctetString encodeValue(final int targetMessageID)
  {
    final ASN1Element[] sequenceValues =
    {
      new ASN1Integer(targetMessageID)
    };

    return new ASN1OctetString(new ASN1Sequence(sequenceValues).encode());
  }

  @Override()
  protected ExtendedResult process(final LDAPConnection connection,
                                   final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_CANCEL_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return super.process(connection, depth);
  }

  public int getTargetMessageID()
  {
    return targetMessageID;
  }

  @Override()
  public CancelExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }

  @Override()
  public CancelExtendedRequest duplicate(final Control[] controls)
  {
    final CancelExtendedRequest cancelRequest =
         new CancelExtendedRequest(targetMessageID, controls);
    cancelRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return cancelRequest;
  }

  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_CANCEL.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("CancelExtendedRequest(targetMessageID=");
    buffer.append(targetMessageID);

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
