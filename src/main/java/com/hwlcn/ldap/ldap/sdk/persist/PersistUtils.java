
package com.hwlcn.ldap.ldap.sdk.persist;



import java.util.UUID;

import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.DNEntrySource;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PersistUtils
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private PersistUtils()
  {

  }



  public static boolean isValidLDAPName(final String s, final StringBuilder r)
  {
    return isValidLDAPName(s, false, r);
  }


  public static boolean isValidLDAPName(final String s, final boolean o,
                                        final StringBuilder r)
  {
    int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      r.append(ERR_LDAP_NAME_VALIDATOR_EMPTY.get());
      return false;
    }

    final String baseName;
    final int semicolonPos = s.indexOf(';');
    if (semicolonPos > 0)
    {
      if (! o)
      {
        r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_CHAR.get(s, ';',
             semicolonPos));
        return false;
      }

      baseName = s.substring(0, semicolonPos);
      length = baseName.length();

      final String optionsStr = s.substring(semicolonPos+1);
      if (! isValidOptionSet(baseName, optionsStr, r))
      {
        return false;
      }
    }
    else
    {
      baseName = s;
    }

    if (isNumericOID(baseName))
    {
      return true;
    }

    for (int i=0; i < length; i++)
    {
      final char c = baseName.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {

      }
      else if (((c >= '0') && (c <= '9')) || (c == '-'))
      {

        if (i == 0)
        {
          r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_FIRST_CHAR.get(s));
          return false;
        }
      }
      else
      {
        r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_CHAR.get(s, c, i));
        return false;
      }
    }

    return true;
  }

  private static boolean isValidOptionSet(final String b, final String o,
                                          final StringBuilder r)
  {
    boolean lastWasSemicolon = true;

    for (int i=0; i < o.length(); i++)
    {
      final char c = o.charAt(i);
      if (c == ';')
      {
        if (lastWasSemicolon)
        {
          r.append(
               ERR_LDAP_NAME_VALIDATOR_OPTION_WITH_CONSECUTIVE_SEMICOLONS.get(
                    b + ';' + o));
          return false;
        }
        else
        {
          lastWasSemicolon = true;
        }
      }
      else
      {
        lastWasSemicolon = false;
        if (((c >= 'a') && (c <= 'z')) ||
            ((c >= 'A') && (c <= 'Z')) ||
            ((c >= '0') && (c <= '9')) ||
            (c == '-'))
        {
          // This will always be acceptable.
        }
        else
        {
          r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_OPTION_CHAR.get(
               (b + ';' + o), c, (b.length() + 1 + i)));
          return false;
        }
      }
    }

    if (lastWasSemicolon)
    {
      r.append(ERR_LDAP_NAME_VALIDATOR_ENDS_WITH_SEMICOLON.get(b + ';' + o));
      return false;
    }

    return true;
  }



  public static boolean isValidJavaIdentifier(final String s,
                                              final StringBuilder r)
  {
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')) ||
          (c == '_'))
      {
        // This will always be acceptable.
      }
      else if ((c >= '0') && (c <= '9'))
      {
        if (i == 0)
        {
          r.append(ERR_JAVA_NAME_VALIDATOR_INVALID_FIRST_CHAR_DIGIT.get(s));
          return false;
        }
      }
      else
      {
        r.append(ERR_JAVA_NAME_VALIDATOR_INVALID_CHAR.get(s, c, i));
        return false;
      }
    }

    return true;
  }


  public static String toJavaIdentifier(final String s)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return toJavaIdentifier(UUID.randomUUID().toString());
    }

    boolean nextUpper = false;
    final StringBuilder b = new StringBuilder(length);
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {
        if (nextUpper)
        {
          b.append(Character.toUpperCase(c));
        }
        else
        {
          b.append(c);
        }

        nextUpper = false;
      }
      else if ((c >= '0') && (c <= '9'))
      {
        if (i == 0)
        {

          b.append('_');
        }

        b.append(c);
        nextUpper = false;
      }
      else
      {

        nextUpper = true;
      }
    }

    if (b.length() == 0)
    {

      return toJavaIdentifier(UUID.randomUUID().toString());
    }

    return b.toString();
  }


  public static <T> T getEntryAsObject(final DN dn, final Class<T> type,
                                       final LDAPInterface conn)
         throws LDAPException
  {
    ensureNotNull(dn, type, conn);

    final LDAPPersister<T> p = LDAPPersister.getInstance(type);

    final Entry e = conn.getEntry(dn.toString(),
         p.getObjectHandler().getAttributesToRequest());
    if (e == null)
    {
      return null;
    }

    return p.decode(e);
  }



  public static <T> PersistedObjects<T> getEntriesAsObjects(final DN[] dns,
                                             final Class<T> type,
                                             final LDAPInterface conn)
         throws LDAPPersistException
  {
    ensureNotNull(dns, type, conn);

    final LDAPPersister<T> p = LDAPPersister.getInstance(type);

    final DNEntrySource entrySource = new DNEntrySource(conn, dns,
         p.getObjectHandler().getAttributesToRequest());
    return new PersistedObjects<T>(p, entrySource);
  }
}
