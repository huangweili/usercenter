package com.hwlcn.ldap.ldif;



import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ChangeType;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModifyRequest;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFModifyChangeRecord
       extends LDIFChangeRecord
{

  private static final long serialVersionUID = 6317289692291736272L;

  private final Modification[] modifications;

  public LDIFModifyChangeRecord(final String dn,
                                final Modification... modifications)
  {
    super(dn);

    ensureNotNull(modifications);
    ensureTrue(modifications.length > 0,
               "LDIFModifyChangeRecord.modifications must not be empty.");

    this.modifications = modifications;
  }

  public LDIFModifyChangeRecord(final String dn,
                                final List<Modification> modifications)
  {
    super(dn);

    ensureNotNull(modifications);
    ensureFalse(modifications.isEmpty(),
                "LDIFModifyChangeRecord.modifications must not be empty.");

    this.modifications = new Modification[modifications.size()];
    modifications.toArray(this.modifications);
  }

  public LDIFModifyChangeRecord(final ModifyRequest modifyRequest)
  {
    super(modifyRequest.getDN());

    final List<Modification> mods = modifyRequest.getModifications();
    modifications = new Modification[mods.size()];

    final Iterator<Modification> iterator = mods.iterator();
    for (int i=0; i < modifications.length; i++)
    {
      modifications[i] = iterator.next();
    }
  }


  public Modification[] getModifications()
  {
    return modifications;
  }

  public ModifyRequest toModifyRequest()
  {
    return new ModifyRequest(getDN(), modifications);
  }

  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY;
  }

  @Override()
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.modify(toModifyRequest());
  }


  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(modifications.length*4);

    ldifLines.add(LDIFWriter.encodeNameAndValue("dn",
                                                new ASN1OctetString(getDN())));
    ldifLines.add("changetype: modify");

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          ldifLines.add("add: " + attrName);
          break;
        case 1:
          ldifLines.add("delete: " + attrName);
          break;
        case 2:
          ldifLines.add("replace: " + attrName);
          break;
        case 3:
          ldifLines.add("increment: " + attrName);
          break;
        default:
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        ldifLines.add(LDIFWriter.encodeNameAndValue(attrName, value));
      }

      if (i < (modifications.length - 1))
      {
        ldifLines.add("-");
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
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("modify"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          LDIFWriter.encodeNameAndValue("add", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 1:
          LDIFWriter.encodeNameAndValue("delete", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 2:
          LDIFWriter.encodeNameAndValue("replace",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 3:
          LDIFWriter.encodeNameAndValue("increment",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        default:
          // This should never happen.
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        LDIFWriter.encodeNameAndValue(attrName, value, buffer, wrapColumn);
        buffer.append(EOL_BYTES);
      }

      if (i < (modifications.length - 1))
      {
        buffer.append('-');
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
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("modify"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          LDIFWriter.encodeNameAndValue("add", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL);
          break;
        case 1:
          LDIFWriter.encodeNameAndValue("delete", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL);
          break;
        case 2:
          LDIFWriter.encodeNameAndValue("replace",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL);
          break;
        case 3:
          LDIFWriter.encodeNameAndValue("increment",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL);
          break;
        default:
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        LDIFWriter.encodeNameAndValue(attrName, value, buffer, wrapColumn);
        buffer.append(EOL);
      }

      if (i < (modifications.length - 1))
      {
        buffer.append('-');
        buffer.append(EOL);
      }
    }
  }

  @Override()
  public int hashCode()
  {
    int hashCode;
    try
    {
      hashCode = getParsedDN().hashCode();
    }
    catch (Exception e)
    {
      debugException(e);
      hashCode = toLowerCase(getDN()).hashCode();
    }

    for (final Modification m : modifications)
    {
      hashCode += m.hashCode();
    }

    return hashCode;
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

    if (! (o instanceof LDIFModifyChangeRecord))
    {
      return false;
    }

    final LDIFModifyChangeRecord r = (LDIFModifyChangeRecord) o;

    try
    {
      if (! getParsedDN().equals(r.getParsedDN()))
      {
        return false;
      }
    }
    catch (Exception e)
    {
      debugException(e);
      if (! toLowerCase(getDN()).equals(toLowerCase(r.getDN())))
      {
        return false;
      }
    }

    if (modifications.length != r.modifications.length)
    {
      return false;
    }

    for (int i=0; i < modifications.length; i++)
    {
      if (! modifications[i].equals(r.modifications[i]))
      {
        return false;
      }
    }

    return true;
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFModifyChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', mods={");

    for (int i=0; i < modifications.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      modifications[i].toString(buffer);
    }

    buffer.append("})");
  }
}
