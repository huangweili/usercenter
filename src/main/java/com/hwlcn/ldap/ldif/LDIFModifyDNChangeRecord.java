package com.hwlcn.ldap.ldif;



import java.util.Arrays;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ChangeType;
import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ModifyDNRequest;
import com.hwlcn.ldap.ldap.sdk.RDN;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFModifyDNChangeRecord
       extends LDIFChangeRecord
{

  private static final long serialVersionUID = -2356367870035948998L;

  private final boolean deleteOldRDN;

  private volatile DN parsedNewSuperiorDN;

  private volatile RDN parsedNewRDN;

  private final String newRDN;

  private final String newSuperiorDN;



  public LDIFModifyDNChangeRecord(final String dn, final String newRDN,
                                  final boolean deleteOldRDN,
                                  final String newSuperiorDN)
  {
    super(dn);

    ensureNotNull(newRDN);

    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }


  public LDIFModifyDNChangeRecord(final ModifyDNRequest modifyDNRequest)
  {
    super(modifyDNRequest.getDN());

    newRDN        = modifyDNRequest.getNewRDN();
    deleteOldRDN  = modifyDNRequest.deleteOldRDN();
    newSuperiorDN = modifyDNRequest.getNewSuperiorDN();
  }

  public String getNewRDN()
  {
    return newRDN;
  }


  public RDN getParsedNewRDN()
         throws LDAPException
  {
    if (parsedNewRDN == null)
    {
      parsedNewRDN = new RDN(newRDN);
    }

    return parsedNewRDN;
  }

  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }


  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }


  public DN getParsedNewSuperiorDN()
         throws LDAPException
  {
    if ((parsedNewSuperiorDN == null) && (newSuperiorDN != null))
    {
      parsedNewSuperiorDN = new DN(newSuperiorDN);
    }

    return parsedNewSuperiorDN;
  }


  public DN getNewDN()
         throws LDAPException
  {
    if (newSuperiorDN == null)
    {
      final DN parentDN = getParsedDN().getParent();
      if (parentDN == null)
      {
        return new DN(getParsedNewRDN());
      }
      else
      {
        return new DN(getParsedNewRDN(), parentDN);
      }
    }
    else
    {
      return new DN(getParsedNewRDN(), getParsedNewSuperiorDN());
    }
  }

  public ModifyDNRequest toModifyDNRequest()
  {
    return new ModifyDNRequest(getDN(), newRDN, deleteOldRDN, newSuperiorDN);
  }


  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY_DN;
  }


  @Override()
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.modifyDN(toModifyDNRequest());
  }


  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines;

    if (newSuperiorDN == null)
    {
      ldifLines = Arrays.asList(
           LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
           "changetype: moddn",
           LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN)),
           "deleteoldrdn: " + (deleteOldRDN ? "1" : "0"));
    }
    else
    {
      ldifLines = Arrays.asList(
           LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
           "changetype: moddn",
           LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN)),
           "deleteoldrdn: " + (deleteOldRDN ? "1" : "0"),
           LDIFWriter.encodeNameAndValue("newsuperior",
                                         new ASN1OctetString(newSuperiorDN)));
    }

    if (wrapColumn > 2)
    {
      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
    }

    final String[] lineArray = new String[ldifLines.size()];
    return ldifLines.toArray(lineArray);
  }

  @Override()
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);

    if (deleteOldRDN)
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("1"),
                                    buffer, wrapColumn);
    }
    else
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("0"),
                                    buffer, wrapColumn);
    }
    buffer.append(EOL_BYTES);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(EOL_BYTES);
    }
  }


  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL);

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(EOL);

    if (deleteOldRDN)
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("1"),
                                    buffer, wrapColumn);
    }
    else
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("0"),
                                    buffer, wrapColumn);
    }
    buffer.append(EOL);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(EOL);
    }
  }


  @Override()
  public int hashCode()
  {
    int hashCode;
    try
    {
      hashCode = getParsedDN().hashCode() + getParsedNewRDN().hashCode();
      if (newSuperiorDN != null)
      {
        hashCode += getParsedNewSuperiorDN().hashCode();
      }
    }
    catch (Exception e)
    {
      debugException(e);
      hashCode = toLowerCase(getDN()).hashCode() +
                 toLowerCase(newRDN).hashCode();
      if (newSuperiorDN != null)
      {
        hashCode += toLowerCase(newSuperiorDN).hashCode();
      }
    }

    if (deleteOldRDN)
    {
      hashCode++;
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

    if (! (o instanceof LDIFModifyDNChangeRecord))
    {
      return false;
    }

    final LDIFModifyDNChangeRecord r = (LDIFModifyDNChangeRecord) o;

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

    try
    {
      if (! getParsedNewRDN().equals(r.getParsedNewRDN()))
      {
        return false;
      }
    }
    catch (Exception e)
    {
      debugException(e);
      if (! toLowerCase(newRDN).equals(toLowerCase(r.newRDN)))
      {
        return false;
      }
    }

    if (newSuperiorDN == null)
    {
      if (r.newSuperiorDN != null)
      {
        return false;
      }
    }
    else
    {
      if (r.newSuperiorDN == null)
      {
        return false;
      }

      try
      {
        if (! getParsedNewSuperiorDN().equals(r.getParsedNewSuperiorDN()))
        {
          return false;
        }
      }
      catch (Exception e)
      {
        debugException(e);
        if (! toLowerCase(newSuperiorDN).equals(toLowerCase(r.newSuperiorDN)))
        {
          return false;
        }
      }
    }

    return (deleteOldRDN == r.deleteOldRDN);
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFModifyDNChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
