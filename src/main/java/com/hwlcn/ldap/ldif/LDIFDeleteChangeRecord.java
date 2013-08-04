package com.hwlcn.ldap.ldif;



import java.util.Arrays;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ChangeType;
import com.hwlcn.ldap.ldap.sdk.DeleteRequest;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFDeleteChangeRecord
       extends LDIFChangeRecord
{

  private static final long serialVersionUID = 486284031156138191L;

  public LDIFDeleteChangeRecord(final String dn)
  {
    super(dn);
  }


  public LDIFDeleteChangeRecord(final DeleteRequest deleteRequest)
  {
    super(deleteRequest.getDN());
  }


  public DeleteRequest toDeleteRequest()
  {
    return new DeleteRequest(getDN());
  }


  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.DELETE;
  }


  @Override()
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.delete(toDeleteRequest());
  }



  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    if (wrapColumn > 0)
    {
      List<String> ldifLines = Arrays.asList(
           LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
           "changetype: delete");

      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);

      final String[] lineArray = new String[ldifLines.size()];
      return ldifLines.toArray(lineArray);
    }
    else
    {
      return new String[]
      {
        LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
        "changetype: delete"
      };
    }
  }



  @Override()
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("delete"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);
  }


  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL);
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("delete"),
                                  buffer, wrapColumn);
    buffer.append(EOL);
  }


  @Override()
  public int hashCode()
  {
    try
    {
      return getParsedDN().hashCode();
    }
    catch (Exception e)
    {
      debugException(e);
      return toLowerCase(getDN()).hashCode();
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

    if (! (o instanceof LDIFDeleteChangeRecord))
    {
      return false;
    }

    final LDIFDeleteChangeRecord r = (LDIFDeleteChangeRecord) o;

    try
    {
      return getParsedDN().equals(r.getParsedDN());
    }
    catch (Exception e)
    {
      debugException(e);
      return toLowerCase(getDN()).equals(toLowerCase(r.getDN()));
    }
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFDeleteChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("')");
  }
}
