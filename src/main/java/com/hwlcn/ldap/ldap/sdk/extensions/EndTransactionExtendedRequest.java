/*
 * Copyright 2010-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2013 UnboundID Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
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



/**
 * This class provides an implementation of the end transaction extended
 * request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc5805.txt">RFC 5805</A>.  It may be used
 * to either commit or abort a transaction that was created using the start
 * transaction request.  See the documentation for the
 * {@link StartTransactionExtendedRequest} class for an example of processing an
 * LDAP transaction.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EndTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.1.21.3) for the end transaction extended request.
   */
  public static final String END_TRANSACTION_REQUEST_OID = "1.3.6.1.1.21.3";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7135468264026410702L;



  // The transaction ID for the associated transaction.
  private final ASN1OctetString transactionID;

  // Indicates whether to commit or abort the associated transaction.
  private final boolean commit;



  /**
   * Creates a new end transaction extended request with the provided
   * information.
   *
   * @param  transactionID  The transaction ID for the transaction to commit or
   *                        abort.  It must not be {@code null}.
   * @param  commit         {@code true} if the transaction should be committed,
   *                        or {@code false} if the transaction should be
   *                        aborted.
   * @param  controls       The set of controls to include in the request.
   */
  public EndTransactionExtendedRequest(final ASN1OctetString transactionID,
                                       final boolean commit,
                                       final Control... controls)
  {
    super(END_TRANSACTION_REQUEST_OID, encodeValue(transactionID, commit),
          controls);

    this.transactionID = transactionID;
    this.commit        = commit;
  }



  /**
   * Creates a new end transaction extended request from the provided generic
   * extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          end transaction extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
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



  /**
   * Generates the value to include in this extended request.
   *
   * @param  transactionID  The transaction ID for the transaction to commit or
   *                        abort.  It must not be {@code null}.
   * @param  commit         {@code true} if the transaction should be committed,
   *                        or {@code false} if the transaction should be
   *                        aborted.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
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



  /**
   * Retrieves the transaction ID for the transaction to commit or abort.
   *
   * @return  The transaction ID for the transaction to commit or abort.
   */
  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }



  /**
   * Indicates whether the transaction should be committed or aborted.
   *
   * @return  {@code true} if the transaction should be committed, or
   *          {@code false} if it should be aborted.
   */
  public boolean commit()
  {
    return commit;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EndTransactionExtendedResult process(final LDAPConnection connection,
                                              final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new EndTransactionExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EndTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EndTransactionExtendedRequest duplicate(final Control[] controls)
  {
    final EndTransactionExtendedRequest r =
         new EndTransactionExtendedRequest(transactionID, commit, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_END_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
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
