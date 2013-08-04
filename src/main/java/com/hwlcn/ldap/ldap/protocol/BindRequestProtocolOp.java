
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.BindRequest;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.GenericSASLBindRequest;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SimpleBindRequest;
import com.hwlcn.ldap.util.LDAPSDKUsageException;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BindRequestProtocolOp
       implements ProtocolOp
{

  public static final byte CRED_TYPE_SIMPLE = (byte) 0x80;


  public static final byte CRED_TYPE_SASL = (byte) 0xA3;


  private static final long serialVersionUID = 6661208657485444954L;




  private final ASN1OctetString saslCredentials;

  private final ASN1OctetString simplePassword;

  private final byte credentialsType;

  private final int version;

  private final String bindDN;

  private final String saslMechanism;


  public BindRequestProtocolOp(final String bindDN, final String password)
  {
    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    if (password == null)
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE);
    }
    else
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    saslMechanism   = null;
    saslCredentials = null;
  }


  public BindRequestProtocolOp(final String bindDN, final byte[] password)
  {
    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    if (password == null)
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE);
    }
    else
    {
      simplePassword = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }

    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    saslMechanism   = null;
    saslCredentials = null;
  }



  public BindRequestProtocolOp(final String bindDN, final String saslMechanism,
                               final ASN1OctetString saslCredentials)
  {
    this.saslMechanism   = saslMechanism;
    this.saslCredentials = saslCredentials;

    if (bindDN == null)
    {
      this.bindDN = "";
    }
    else
    {
      this.bindDN = bindDN;
    }

    version         = 3;
    credentialsType = CRED_TYPE_SASL;
    simplePassword  = null;
  }



  public BindRequestProtocolOp(final SimpleBindRequest request)
         throws LDAPSDKUsageException
  {
    version         = 3;
    credentialsType = CRED_TYPE_SIMPLE;
    bindDN          = request.getBindDN();
    simplePassword  = request.getPassword();
    saslMechanism   = null;
    saslCredentials = null;

    if (simplePassword == null)
    {
      throw new LDAPSDKUsageException(
           ERR_BIND_REQUEST_CANNOT_CREATE_WITH_PASSWORD_PROVIDER.get());
    }
  }




  public BindRequestProtocolOp(final GenericSASLBindRequest request)
  {
    version         = 3;
    credentialsType = CRED_TYPE_SASL;
    bindDN          = request.getBindDN();
    simplePassword  = null;
    saslMechanism   = request.getSASLMechanismName();
    saslCredentials = request.getCredentials();
  }




  BindRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      version         = reader.readInteger();
      bindDN          = reader.readString();
      credentialsType = (byte) reader.peek();

      ensureNotNull(bindDN);

      switch (credentialsType)
      {
        case CRED_TYPE_SIMPLE:
          simplePassword =
               new ASN1OctetString(credentialsType, reader.readBytes());
          saslMechanism   = null;
          saslCredentials = null;
          ensureNotNull(bindDN);
          break;

        case CRED_TYPE_SASL:
          final ASN1StreamReaderSequence saslSequence = reader.beginSequence();
          saslMechanism = reader.readString();
          ensureNotNull(saslMechanism);
          if (saslSequence.hasMoreElements())
          {
            saslCredentials = new ASN1OctetString(reader.readBytes());
          }
          else
          {
            saslCredentials = null;
          }
          simplePassword = null;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_REQUEST_INVALID_CRED_TYPE.get(toHex(credentialsType)));
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_BIND_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  private BindRequestProtocolOp(final int version, final String bindDN,
                                final byte credentialsType,
                                final ASN1OctetString simplePassword,
                                final String saslMechanism,
                                final ASN1OctetString saslCredentials)
  {
    this.version         = version;
    this.bindDN          = bindDN;
    this.credentialsType = credentialsType;
    this.simplePassword  = simplePassword;
    this.saslMechanism   = saslMechanism;
    this.saslCredentials = saslCredentials;
  }



  public int getVersion()
  {
    return version;
  }


  public String getBindDN()
  {
    return bindDN;
  }


  public byte getCredentialsType()
  {
    return credentialsType;
  }

  public ASN1OctetString getSimplePassword()
  {
    return simplePassword;
  }


  public String getSASLMechanism()
  {
    return saslMechanism;
  }


  public ASN1OctetString getSASLCredentials()
  {
    return saslCredentials;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }


  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element credentials;
    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      credentials = simplePassword;
    }
    else
    {
      if (saslCredentials == null)
      {
        credentials = new ASN1Sequence(CRED_TYPE_SASL,
             new ASN1OctetString(saslMechanism));
      }
      else
      {
        credentials = new ASN1Sequence(CRED_TYPE_SASL,
             new ASN1OctetString(saslMechanism),
             saslCredentials);
      }
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
         new ASN1Integer(version),
         new ASN1OctetString(bindDN),
         credentials);
  }



  public static BindRequestProtocolOp decodeProtocolOp(
                                           final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final int version = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      final String bindDN =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();

      final ASN1OctetString saslCredentials;
      final ASN1OctetString simplePassword;
      final String saslMechanism;
      switch (elements[2].getType())
      {
        case CRED_TYPE_SIMPLE:
          simplePassword  = ASN1OctetString.decodeAsOctetString(elements[2]);
          saslMechanism   = null;
          saslCredentials = null;
          break;

        case CRED_TYPE_SASL:
          final ASN1Element[] saslElements =
               ASN1Sequence.decodeAsSequence(elements[2]).elements();
          saslMechanism = ASN1OctetString.decodeAsOctetString(saslElements[0]).
               stringValue();
          if (saslElements.length == 1)
          {
            saslCredentials = null;
          }
          else
          {
            saslCredentials =
                 ASN1OctetString.decodeAsOctetString(saslElements[1]);
          }

          simplePassword = null;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_REQUEST_INVALID_CRED_TYPE.get(
                    toHex(elements[2].getType())));
      }

      return new BindRequestProtocolOp(version, bindDN, elements[2].getType(),
           simplePassword, saslMechanism, saslCredentials);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_BIND_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
    buffer.addInteger(version);
    buffer.addOctetString(bindDN);

    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      buffer.addElement(simplePassword);
    }
    else
    {
      final ASN1BufferSequence saslSequence =
           buffer.beginSequence(CRED_TYPE_SASL);
      buffer.addOctetString(saslMechanism);
      if (saslCredentials != null)
      {
        buffer.addElement(saslCredentials);
      }
      saslSequence.end();
    }
    opSequence.end();
    buffer.setZeroBufferOnClear();
  }



  public BindRequest toBindRequest(final Control... controls)
  {
    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      return new SimpleBindRequest(bindDN, simplePassword.getValue(),
           controls);
    }
    else
    {
      return new GenericSASLBindRequest(bindDN, saslMechanism,
           saslCredentials, controls);
    }
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("BindRequestProtocolOp(version=");
    buffer.append(version);
    buffer.append(", bindDN='");
    buffer.append(bindDN);
    buffer.append("', type=");

    if (credentialsType == CRED_TYPE_SIMPLE)
    {
      buffer.append("simple");
    }
    else
    {
      buffer.append("SASL, mechanism=");
      buffer.append(saslMechanism);
    }

    buffer.append(')');
  }
}
