package com.hwlcn.ldap.ldap.sdk;



import javax.security.sasl.SaslClient;

import com.hwlcn.ldap.asn1.ASN1OctetString;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

final class SASLHelper
{
  private final Control[] controls;

  private final int messageID;

  private final LDAPConnection connection;

  private final long responseTimeoutMillis;

  private final SASLBindRequest bindRequest;

  private final SaslClient saslClient;

  private final String mechanism;



  SASLHelper(final SASLBindRequest bindRequest, final LDAPConnection connection,
             final String mechanism, final SaslClient saslClient,
             final Control[] controls, final long responseTimeoutMillis)
  {
    this.bindRequest           = bindRequest;
    this.connection            = connection;
    this.mechanism             = mechanism;
    this.saslClient            = saslClient;
    this.controls              = controls;
    this.responseTimeoutMillis = responseTimeoutMillis;

    messageID = -1;
  }


  BindResult processSASLBind()
         throws LDAPException
  {
    try
    {
      byte[] credBytes = null;
      try
      {
        if (saslClient.hasInitialResponse())
        {
          credBytes = saslClient.evaluateChallenge(new byte[0]);
        }
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SASL_CANNOT_CREATE_INITIAL_REQUEST.get(mechanism,
                  getExceptionMessage(e)), e);
      }

      ASN1OctetString saslCredentials;
      if ((credBytes == null) || (credBytes.length == 0))
      {
        saslCredentials = null;
      }
      else
      {
        saslCredentials = new ASN1OctetString(credBytes);
      }

      BindResult bindResult = bindRequest.sendBindRequest(connection, "",
           saslCredentials, controls, responseTimeoutMillis);

      if (! bindResult.getResultCode().equals(ResultCode.SASL_BIND_IN_PROGRESS))
      {
        return bindResult;
      }

      byte[] serverCredBytes = bindResult.getServerSASLCredentials().getValue();

      while (true)
      {
        try
        {
          credBytes = saslClient.evaluateChallenge(serverCredBytes);
        }
        catch (Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SASL_CANNOT_CREATE_SUBSEQUENT_REQUEST.get(mechanism,
                    getExceptionMessage(e)), e);
        }

        if ((credBytes == null) || (credBytes.length == 0))
        {
          saslCredentials = null;
        }
        else
        {
          saslCredentials = new ASN1OctetString(credBytes);
        }

        bindResult = bindRequest.sendBindRequest(connection, "",
             saslCredentials, controls, responseTimeoutMillis);
        if (! bindResult.getResultCode().equals(
                   ResultCode.SASL_BIND_IN_PROGRESS))
        {
          return bindResult;
        }

        serverCredBytes = bindResult.getServerSASLCredentials().getValue();
      }
    }
    finally
    {
      try
      {
        saslClient.dispose();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }


  int getMessageID()
  {
    return messageID;
  }
}
