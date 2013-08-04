package com.hwlcn.ldap.ldif;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.AddRequest;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.ChangeType;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFAddChangeRecord
       extends LDIFChangeRecord
{

  private static final long serialVersionUID = 5717427836786488295L;

  private final Attribute[] attributes;

  public LDIFAddChangeRecord(final String dn, final Attribute... attributes)
  {
    super(dn);

    ensureNotNull(attributes);
    ensureTrue(attributes.length > 0,
               "LDIFAddChangeRecord.attributes must not be empty.");

    this.attributes = attributes;
  }

  public LDIFAddChangeRecord(final String dn, final List<Attribute> attributes)
  {
    super(dn);

    ensureNotNull(attributes);
    ensureFalse(attributes.isEmpty(),
                "LDIFAddChangeRecord.attributes must not be empty.");

    this.attributes = new Attribute[attributes.size()];
    attributes.toArray(this.attributes);
  }


  public LDIFAddChangeRecord(final Entry entry)
  {
    super(entry.getDN());

    final Collection<Attribute> attrs = entry.getAttributes();
    attributes = new Attribute[attrs.size()];

    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = iterator.next();
    }
  }


  public LDIFAddChangeRecord(final AddRequest addRequest)
  {
    super(addRequest.getDN());

    final List<Attribute> attrs = addRequest.getAttributes();
    attributes = new Attribute[attrs.size()];

    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = iterator.next();
    }
  }

  public Attribute[] getAttributes()
  {
    return attributes;
  }


  public Entry getEntryToAdd()
  {
    return new Entry(getDN(), attributes);
  }


  public AddRequest toAddRequest()
  {
    return new AddRequest(getDN(), attributes);
  }



  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.ADD;
  }


  @Override()
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.add(toAddRequest());
  }



  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(2*attributes.length);
    ldifLines.add(LDIFWriter.encodeNameAndValue("dn",
                                                new ASN1OctetString(getDN())));
    ldifLines.add("changetype: add");

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        ldifLines.add(LDIFWriter.encodeNameAndValue(name, value));
      }
    }

    if (wrapColumn > 2)
    {
      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
    }

    final String[] ldifArray = new String[ldifLines.size()];
    ldifLines.toArray(ldifArray);
    return ldifArray;
  }


  @Override()
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(EOL_BYTES);
      }
    }
  }


  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL);

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(EOL);
      }
    }
  }


  @Override()
  public int hashCode()
  {
    try
    {
      int hashCode = getParsedDN().hashCode();
      for (final Attribute a : attributes)
      {
        hashCode += a.hashCode();
      }

      return hashCode;
    }
    catch (Exception e)
    {
      debugException(e);
      return new Entry(getDN(), attributes).hashCode();
    }
  }

  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDIFAddChangeRecord))
    {
      return false;
    }

    final LDIFAddChangeRecord r = (LDIFAddChangeRecord) o;

    final Entry e1 = new Entry(getDN(), attributes);
    final Entry e2 = new Entry(r.getDN(), r.attributes);
    return e1.equals(e2);
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFAddChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', attrs={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      attributes[i].toString(buffer);
    }

    buffer.append("})");
  }
}
