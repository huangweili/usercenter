package com.hwlcn.ldap.ldap.sdk.extensions;



import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
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
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EndTransactionExtendedRequest
       extends ExtendedRequest
{

  public static final String END_TRANSACTION_REQUEST_OID = "1.3.6.1.1.21.3";

  private static final long serialVersionUID = -7135468264026410702L;

  private final ASN1OctetString transactionID;

  private final boolean commit;

  public EndTransactionExtendedRequest(final ASN1OctetString transactionID,
                                       final boolean commit,
                                       final Control... controls)
  {
    super(END_TRANSACTION_REQUEST_OID, encodeValue(transactionID, commit),
          controls);

    this.transactionID = transactionID;
    this.commit        = commit;
  }

  public EndTransactionExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      if (elements.length == 1)
      {
        commit        = true;
        transactionID = ASN1OctetString.decodeAsOctetString(elements[0]);
      }
      else
      {
        commit        = ASN1Boolean.decodeAsBoolean(elements[0]).booleanValue();
        transactionID = ASN1OctetString.decodeAsOctetString(elements[1]);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }

  private static ASN1OctetString
       encodeValue(final ASN1OctetString transactionID,
                   final boolean commit)
  {
    ensureNotNull(transactionID);

    final ASN1Element[] valueElements;
    if (commit)
    {
      valueElements = new ASN1Element[]
      {
        transactionID
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Boolean(commit),
        transactionID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }

  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }

  public boolean commit()
  {
    return commit;
  }

  @Override()
  public EndTransactionExtendedResult process(final LDAPConnection connection,
                                              final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new EndTransactionExtendedResult(extendedResponse);
  }

  @Override()
  public EndTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }

  @Override()
  public EndTransactionExtendedRequest duplicate(final Control[] controls)
  {
    final EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(transactionID, commit, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }

  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_END_TXN.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EndTransactionExtendedRequest(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("', commit=");
    buffer.append(commit);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
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
