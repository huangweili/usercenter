package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultEntry
       extends ReadOnlyEntry
       implements LDAPResponse
{

  private static final long serialVersionUID = -290721544252526163L;

  private final Control[] controls;

  private final int messageID;


  public SearchResultEntry(final String dn, final Attribute[] attributes,
                           final Control... controls)
  {
    this(-1, dn, null, attributes, controls);
  }



  public SearchResultEntry(final int messageID, final String dn,
                           final Attribute[] attributes,
                           final Control... controls)
  {
    this(messageID, dn, null, attributes, controls);
  }

  public SearchResultEntry(final int messageID, final String dn,
                           final Schema schema, final Attribute[] attributes,
                           final Control... controls)
  {
    super(dn, schema, attributes);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }


  public SearchResultEntry(final String dn,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    this(-1, dn, null, attributes, controls);
  }


  public SearchResultEntry(final int messageID, final String dn,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    this(messageID, dn, null, attributes, controls);
  }


  public SearchResultEntry(final int messageID, final String dn,
                           final Schema schema,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    super(dn, schema, attributes);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }



  public SearchResultEntry(final Entry entry, final Control... controls)
  {
    this(-1, entry, controls);
  }

  public SearchResultEntry(final int messageID, final Entry entry,
                           final Control... controls)
  {
    super(entry);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }



  static SearchResultEntry readSearchEntryFrom(final int messageID,
              final ASN1StreamReaderSequence messageSequence,
              final ASN1StreamReader reader, final Schema schema)
         throws LDAPException
  {
    try
    {
      reader.beginSequence();
      final String dn = reader.readString();

      final ArrayList<Attribute> attrList = new ArrayList<Attribute>(10);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrList.add(Attribute.readFrom(reader, schema));
      }

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

      return new SearchResultEntry(messageID, dn, schema, attrList, controls);
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
           ERR_SEARCH_ENTRY_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public int getMessageID()
  {
    return messageID;
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
  public int hashCode()
  {
    int hashCode = super.hashCode();

    for (final Control c : controls)
    {
      hashCode += c.hashCode();
    }

    return hashCode;
  }



  @Override()
  public boolean equals(final Object o)
  {
    if (! super.equals(o))
    {
      return false;
    }

    if (! (o instanceof SearchResultEntry))
    {
      return false;
    }

    final SearchResultEntry e = (SearchResultEntry) o;

    if (controls.length != e.controls.length)
    {
      return false;
    }

    for (int i=0; i < controls.length; i++)
    {
      if (! controls[i].equals(e.controls[i]))
      {
        return false;
      }
    }

    return true;
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchResultEntry(dn='");
    buffer.append(getDN());
    buffer.append('\'');

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", attributes={");

    final Iterator<Attribute> iterator = getAttributes().iterator();

    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, controls={");

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
