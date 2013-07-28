package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class BindResult
       extends LDAPResult
{

  private static final byte TYPE_SERVER_SASL_CREDENTIALS = (byte) 0x87;



  private static final long serialVersionUID = 2211625049303605730L;



  private final ASN1OctetString serverSASLCredentials;



  public BindResult(final int messageID, final ResultCode resultCode,
                    final String diagnosticMessage, final String matchedDN,
                    final String[] referralURLs,
                    final Control[] responseControls)
  {
    this(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         responseControls, null);
  }



  public BindResult(final int messageID, final ResultCode resultCode,
                    final String diagnosticMessage, final String matchedDN,
                    final String[] referralURLs,
                    final Control[] responseControls,
                    final ASN1OctetString serverSASLCredentials)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.serverSASLCredentials = serverSASLCredentials;
  }




  public BindResult(final LDAPResult ldapResult)
  {
    super(ldapResult);

    serverSASLCredentials = null;
  }



  protected BindResult(final BindResult bindResult)
  {
    super(bindResult);

    serverSASLCredentials = bindResult.serverSASLCredentials;
  }



  static BindResult readBindResultFrom(final int messageID,
                         final ASN1StreamReaderSequence messageSequence,
                         final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence protocolOpSequence =
           reader.beginSequence();
      final ResultCode resultCode = ResultCode.valueOf(reader.readEnumerated());

      String matchedDN = reader.readString();
      if (matchedDN.length() == 0)
      {
        matchedDN = null;
      }

      String diagnosticMessage = reader.readString();
      if (diagnosticMessage.length() == 0)
      {
        diagnosticMessage = null;
      }

      String[] referralURLs = null;
      ASN1OctetString serverSASLCredentials = null;
      while (protocolOpSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case TYPE_REFERRAL_URLS:
            final ArrayList<String> refList = new ArrayList<String>(1);
            final ASN1StreamReaderSequence refSequence = reader.beginSequence();
            while (refSequence.hasMoreElements())
            {
              refList.add(reader.readString());
            }
            referralURLs = new String[refList.size()];
            refList.toArray(referralURLs);
            break;

          case TYPE_SERVER_SASL_CREDENTIALS:
            serverSASLCredentials =
                 new ASN1OctetString(type, reader.readBytes());
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_BIND_RESULT_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      Control[] controls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }

      return new BindResult(messageID, resultCode, diagnosticMessage, matchedDN,
                            referralURLs, controls, serverSASLCredentials);
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
           ERR_BIND_RESULT_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public ASN1OctetString getServerSASLCredentials()
  {
    return serverSASLCredentials;
  }
}
