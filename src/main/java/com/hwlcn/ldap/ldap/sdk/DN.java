package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DN
       implements Comparable<DN>, Comparator<DN>, Serializable
{

  private static final RDN[] NO_RDNS = new RDN[0];



  public static final DN NULL_DN = new DN();


  private static final long serialVersionUID = -5272968942085729346L;

  private final RDN[] rdns;

  private final Schema schema;

  private final String dnString;

  private volatile String normalizedString;



  public DN(final RDN... rdns)
  {
    ensureNotNull(rdns);

    this.rdns = rdns;
    if (rdns.length == 0)
    {
      dnString         = "";
      normalizedString = "";
      schema           = null;
    }
    else
    {
      Schema s = null;
      final StringBuilder buffer = new StringBuilder();
      for (final RDN rdn : rdns)
      {
        if (buffer.length() > 0)
        {
          buffer.append(',');
        }
        rdn.toString(buffer, false);

        if (s == null)
        {
          s = rdn.getSchema();
        }
      }

      dnString = buffer.toString();
      schema   = s;
    }
  }




  public DN(final List<RDN> rdns)
  {
    ensureNotNull(rdns);

    if (rdns.isEmpty())
    {
      this.rdns        = NO_RDNS;
      dnString         = "";
      normalizedString = "";
      schema           = null;
    }
    else
    {
      this.rdns = rdns.toArray(new RDN[rdns.size()]);

      Schema s = null;
      final StringBuilder buffer = new StringBuilder();
      for (final RDN rdn : this.rdns)
      {
        if (buffer.length() > 0)
        {
          buffer.append(',');
        }
        rdn.toString(buffer, false);

        if (s == null)
        {
          s = rdn.getSchema();
        }
      }

      dnString = buffer.toString();
      schema   = s;
    }
  }


  public DN(final RDN rdn, final DN parentDN)
  {
    ensureNotNull(rdn, parentDN);

    rdns = new RDN[parentDN.rdns.length + 1];
    rdns[0] = rdn;
    System.arraycopy(parentDN.rdns, 0, rdns, 1, parentDN.rdns.length);

    Schema s = null;
    final StringBuilder buffer = new StringBuilder();
    for (final RDN r : rdns)
    {
      if (buffer.length() > 0)
      {
        buffer.append(',');
      }
      r.toString(buffer, false);

      if (s == null)
      {
        s = r.getSchema();
      }
    }

    dnString = buffer.toString();
    schema   = s;
  }




  public DN(final String dnString)
         throws LDAPException
  {
    this(dnString, null);
  }



  public DN(final String dnString, final Schema schema)
         throws LDAPException
  {
    ensureNotNull(dnString);

    this.dnString = dnString;
    this.schema   = schema;

    final ArrayList<RDN> rdnList = new ArrayList<RDN>(5);

    final int length = dnString.length();
    if (length == 0)
    {
      rdns             = NO_RDNS;
      normalizedString = "";
      return;
    }

    int pos = 0;
    boolean expectMore = false;
rdnLoop:
    while (pos < length)
    {

      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if (pos >= length)
      {

        if (rdnList.isEmpty())
        {
          break;
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_ENDS_WITH_COMMA.get());
        }
      }


      int rdnEndPos;
      int rdnStartPos = pos;
      int attrStartPos = pos;
      while (pos < length)
      {
        final char c = dnString.charAt(pos);
        if ((c == ' ') || (c == '='))
        {
          break;
        }
        else if ((c == ',') || (c == ';'))
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_UNEXPECTED_COMMA.get(pos));
        }

        pos++;
      }

      String attrName = dnString.substring(attrStartPos, pos);
      if (attrName.length() == 0)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_DN_NO_ATTR_IN_RDN.get());
      }



      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if ((pos >= length) || (dnString.charAt(pos) != '='))
      {

        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_DN_NO_EQUAL_SIGN.get(attrName));
      }


      pos++;
      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }



      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_DN_NO_VALUE_FOR_ATTR.get(attrName));
      }



      ASN1OctetString value;
      if (dnString.charAt(pos) == '#')
      {

        final byte[] valueArray = RDN.readHexString(dnString, ++pos);
        value = new ASN1OctetString(valueArray);
        pos += (valueArray.length * 2);
        rdnEndPos = pos;
      }
      else
      {

        final StringBuilder buffer = new StringBuilder();
        pos = RDN.readValueString(dnString, pos, buffer);
        value = new ASN1OctetString(buffer.toString());
        rdnEndPos = pos;
      }



      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if (pos >= length)
      {

        rdnList.add(new RDN(attrName, value, schema,
             getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
        expectMore = false;
        break;
      }

      switch (dnString.charAt(pos))
      {
        case '+':

          pos++;
          break;

        case ',':
        case ';':

          rdnList.add(new RDN(attrName, value, schema,
               getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
          pos++;
          expectMore = true;
          continue rdnLoop;

        default:

          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_UNEXPECTED_CHAR.get(
                                       dnString.charAt(pos), pos));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_DN_ENDS_WITH_PLUS.get());
      }



      final ArrayList<String> nameList = new ArrayList<String>(5);
      final ArrayList<ASN1OctetString> valueList =
           new ArrayList<ASN1OctetString>(5);
      nameList.add(attrName);
      valueList.add(value);

      while (pos < length)
      {

        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        if (pos >= length)
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_ENDS_WITH_PLUS.get());
        }


        attrStartPos = pos;
        while (pos < length)
        {
          final char c = dnString.charAt(pos);
          if ((c == ' ') || (c == '='))
          {
            break;
          }
          else if ((c == ',') || (c == ';'))
          {
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                    ERR_DN_UNEXPECTED_COMMA.get(pos));
          }

          pos++;
        }

        attrName = dnString.substring(attrStartPos, pos);
        if (attrName.length() == 0)
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_NO_ATTR_IN_RDN.get());
        }

        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        if ((pos >= length) || (dnString.charAt(pos) != '='))
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_NO_EQUAL_SIGN.get(attrName));
        }

        pos++;
        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        if (pos >= length)
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_DN_NO_VALUE_FOR_ATTR.get(attrName));
        }

        if (dnString.charAt(pos) == '#')
        {
          final byte[] valueArray = RDN.readHexString(dnString, ++pos);
          value = new ASN1OctetString(valueArray);
          pos += (valueArray.length * 2);
          rdnEndPos = pos;
        }
        else
        {
          final StringBuilder buffer = new StringBuilder();
          pos = RDN.readValueString(dnString, pos, buffer);
          value = new ASN1OctetString(buffer.toString());
          rdnEndPos = pos;
        }

        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        nameList.add(attrName);
        valueList.add(value);

        if (pos >= length)
        {
          final String[] names = nameList.toArray(new String[nameList.size()]);
          final ASN1OctetString[] values =
               valueList.toArray(new ASN1OctetString[valueList.size()]);
          rdnList.add(new RDN(names, values, schema,
               getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
          expectMore = false;
          break rdnLoop;
        }

        switch (dnString.charAt(pos))
        {
          case '+':
            pos++;

            if (pos >= length)
            {
              throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                      ERR_DN_ENDS_WITH_PLUS.get());
            }
            break;

          case ',':
          case ';':
            final String[] names =
                 nameList.toArray(new String[nameList.size()]);
            final ASN1OctetString[] values =
                 valueList.toArray(new ASN1OctetString[valueList.size()]);
            rdnList.add(new RDN(names, values, schema,
                 getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
            pos++;
            expectMore = true;
            continue rdnLoop;

          default:
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                    ERR_DN_UNEXPECTED_CHAR.get(
                                         dnString.charAt(pos), pos));
        }
      }
    }

    if (expectMore)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_DN_ENDS_WITH_COMMA.get());
    }

    rdns = new RDN[rdnList.size()];
    rdnList.toArray(rdns);
  }


  private static String getTrimmedRDN(final String dnString, final int start,
                                      final int end)
  {
    final String rdnString = dnString.substring(start, end);
    if (! rdnString.endsWith(" "))
    {
      return rdnString;
    }

    final StringBuilder buffer = new StringBuilder(rdnString);
    while ((buffer.charAt(buffer.length() - 1) == ' ') &&
           (buffer.charAt(buffer.length() - 2) != '\\'))
    {
      buffer.setLength(buffer.length() - 1);
    }

    return buffer.toString();
  }

  public static boolean isValidDN(final String s)
  {
    try
    {
      new DN(s);
      return true;
    }
    catch (LDAPException le)
    {
      return false;
    }
  }



  public RDN getRDN()
  {
    if (rdns.length == 0)
    {
      return null;
    }
    else
    {
      return rdns[0];
    }
  }


  public String getRDNString()
  {
    if (rdns.length == 0)
    {
      return null;
    }
    else
    {
      return rdns[0].toString();
    }
  }


  public static String getRDNString(final String s)
         throws LDAPException
  {
    return new DN(s).getRDNString();
  }


  public RDN[] getRDNs()
  {
    return rdns;
  }

  public static RDN[] getRDNs(final String s)
         throws LDAPException
  {
    return new DN(s).getRDNs();
  }



  public String[] getRDNStrings()
  {
    final String[] rdnStrings = new String[rdns.length];
    for (int i=0; i < rdns.length; i++)
    {
      rdnStrings[i] = rdns[i].toString();
    }
    return rdnStrings;
  }


  public static String[] getRDNStrings(final String s)
         throws LDAPException
  {
    return new DN(s).getRDNStrings();
  }


  public boolean isNullDN()
  {
    return (rdns.length == 0);
  }


  public DN getParent()
  {
    switch (rdns.length)
    {
      case 0:
      case 1:
        return null;

      case 2:
        return new DN(rdns[1]);

      case 3:
        return new DN(rdns[1], rdns[2]);

      case 4:
        return new DN(rdns[1], rdns[2], rdns[3]);

      case 5:
        return new DN(rdns[1], rdns[2], rdns[3], rdns[4]);

      default:
        final RDN[] parentRDNs = new RDN[rdns.length - 1];
        System.arraycopy(rdns, 1, parentRDNs, 0, parentRDNs.length);
        return new DN(parentRDNs);
    }
  }


  public static DN getParent(final String s)
         throws LDAPException
  {
    return new DN(s).getParent();
  }


  public String getParentString()
  {
    final DN parentDN = getParent();
    if (parentDN == null)
    {
      return null;
    }
    else
    {
      return parentDN.toString();
    }
  }


  public static String getParentString(final String s)
         throws LDAPException
  {
    return new DN(s).getParentString();
  }


  public boolean isAncestorOf(final DN dn, final boolean allowEquals)
  {
    int thisPos = rdns.length - 1;
    int thatPos = dn.rdns.length - 1;

    if (thisPos < 0)
    {

      return (allowEquals || (thatPos >= 0));
    }

    if ((thisPos > thatPos) || ((thisPos == thatPos) && (! allowEquals)))
    {

      return false;
    }

    while (thisPos >= 0)
    {
      if (! rdns[thisPos--].equals(dn.rdns[thatPos--]))
      {
        return false;
      }
    }

    return true;
  }


  public boolean isAncestorOf(final String s, final boolean allowEquals)
         throws LDAPException
  {
    return isAncestorOf(new DN(s), allowEquals);
  }



  public static boolean isAncestorOf(final String s1, final String s2,
                                     final boolean allowEquals)
         throws LDAPException
  {
    return new DN(s1).isAncestorOf(new DN(s2), allowEquals);
  }

  public boolean isDescendantOf(final DN dn, final boolean allowEquals)
  {
    int thisPos = rdns.length - 1;
    int thatPos = dn.rdns.length - 1;

    if (thatPos < 0)
    {
      return (allowEquals || (thisPos >= 0));
    }

    if ((thisPos < thatPos) || ((thisPos == thatPos) && (! allowEquals)))
    {
      return false;
    }

    while (thatPos >= 0)
    {
      if (! rdns[thisPos--].equals(dn.rdns[thatPos--]))
      {
        return false;
      }
    }

    return true;
  }


  public boolean isDescendantOf(final String s, final boolean allowEquals)
         throws LDAPException
  {
    return isDescendantOf(new DN(s), allowEquals);
  }


  public static boolean isDescendantOf(final String s1, final String s2,
                                       final boolean allowEquals)
         throws LDAPException
  {
    return new DN(s1).isDescendantOf(new DN(s2), allowEquals);
  }



  public boolean matchesBaseAndScope(final String baseDN,
                                     final SearchScope scope)
         throws LDAPException
  {
    return matchesBaseAndScope(new DN(baseDN), scope);
  }



  public boolean matchesBaseAndScope(final DN baseDN, final SearchScope scope)
         throws LDAPException
  {
    ensureNotNull(baseDN, scope);

    switch (scope.intValue())
    {
      case SearchScope.BASE_INT_VALUE:
        return equals(baseDN);

      case SearchScope.ONE_INT_VALUE:
        return baseDN.equals(getParent());

      case SearchScope.SUB_INT_VALUE:
        return isDescendantOf(baseDN, true);

      case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
        return isDescendantOf(baseDN, false);

      default:
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_DN_MATCHES_UNSUPPORTED_SCOPE.get(dnString,
                  String.valueOf(scope)));
    }
  }



  @Override() public int hashCode()
  {
    return toNormalizedString().hashCode();
  }


  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (this == o)
    {
      return true;
    }

    if (! (o instanceof DN))
    {
      return false;
    }

    final DN dn = (DN) o;
    return (toNormalizedString().equals(dn.toNormalizedString()));
  }


  public boolean equals(final String s)
         throws LDAPException
  {
    if (s == null)
    {
      return false;
    }

    return equals(new DN(s));
  }


  public static boolean equals(final String s1, final String s2)
         throws LDAPException
  {
    return new DN(s1).equals(new DN(s2));
  }

  @Override()
  public String toString()
  {
    return dnString;
  }


  public String toMinimallyEncodedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, true);
    return buffer.toString();
  }

  public void toString(final StringBuilder buffer)
  {
    toString(buffer, false);
  }

  public void toString(final StringBuilder buffer,
                       final boolean minimizeEncoding)
  {
    for (int i=0; i < rdns.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      rdns[i].toString(buffer, minimizeEncoding);
    }
  }

  public String toNormalizedString()
  {
    if (normalizedString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedString = buffer.toString();
    }

    return normalizedString;
  }

  public void toNormalizedString(final StringBuilder buffer)
  {
    for (int i=0; i < rdns.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(rdns[i].toNormalizedString());
    }
  }


  public static String normalize(final String s)
         throws LDAPException
  {
    return normalize(s, null);
  }


  public static String normalize(final String s, final Schema schema)
         throws LDAPException
  {
    return new DN(s, schema).toNormalizedString();
  }

  public int compareTo(final DN dn)
  {
    return compare(this, dn);
  }


  public int compare(final DN dn1, final DN dn2)
  {
    ensureNotNull(dn1, dn2);

    int pos1 = dn1.rdns.length - 1;
    int pos2 = dn2.rdns.length - 1;
    if (pos1 < 0)
    {
      if (pos2 < 0)
      {
        return 0;
      }
      else
      {
        return -1;
      }
    }
    else if (pos2 < 0)
    {
      return 1;
    }


    while ((pos1 >= 0) && (pos2 >= 0))
    {
      final int compValue = dn1.rdns[pos1].compareTo(dn2.rdns[pos2]);
      if (compValue != 0)
      {
        return compValue;
      }

      pos1--;
      pos2--;
    }


    if (pos1 < 0)
    {
      if (pos2 < 0)
      {
        return 0;
      }
      else
      {
        return -1;
      }
    }
    else
    {
      return 1;
    }
  }



  public static int compare(final String s1, final String s2)
         throws LDAPException
  {
    return compare(s1, s2, null);
  }



  public static int compare(final String s1, final String s2,
                            final Schema schema)
         throws LDAPException
  {
    return new DN(s1, schema).compareTo(new DN(s2, schema));
  }
}
