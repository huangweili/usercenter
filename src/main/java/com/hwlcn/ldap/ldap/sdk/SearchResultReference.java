package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReference
       implements Serializable, LDAPResponse
{

  private static final long serialVersionUID = 5675961266319346053L;


  private final Control[] controls;

  private final int messageID;

  private final String[] referralURLs;



  public SearchResultReference(final String[] referralURLs,
                               final Control[] controls)
  {
    this(-1, referralURLs, controls);
  }




  public SearchResultReference(final int messageID, final String[] referralURLs,
                               final Control[] controls)
  {
    ensureNotNull(referralURLs);

    this.messageID    = messageID;
    this.referralURLs = referralURLs;

    if (controls == null)
    {
      this.controls = NO_CONTROLS;
    }
    else
    {
      this.controls = controls;
    }
  }




  static SearchResultReference readSearchReferenceFrom(final int messageID,
              final ASN1StreamReaderSequence messageSequence,
              final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ArrayList<String> refList = new ArrayList<String>(5);
      final ASN1StreamReaderSequence refSequence = reader.beginSequence();
      while (refSequence.hasMoreElements())
      {
        refList.add(reader.readString());
      }

      final String[] referralURLs = new String[refList.size()];
      refList.toArray(referralURLs);

      Control[] controls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(5);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }

      return new SearchResultReference(messageID, referralURLs, controls);
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
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public int getMessageID()
  {
    return messageID;
  }


  public String[] getReferralURLs()
  {
    return referralURLs;
  }



  public Control[] getControls()
  {
    return controls;
  }


  public Control getControl(final String oid)
  {
    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
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
    buffer.append("SearchResultReference(referralURLs={");
    for (int i=0; i < referralURLs.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append(referralURLs[i]);
    }
    buffer.append('}');

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", controls={");

    for (int i=0; i < controls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      controls[i].toString(buffer);
    }

    buffer.append("})");
  }
}
