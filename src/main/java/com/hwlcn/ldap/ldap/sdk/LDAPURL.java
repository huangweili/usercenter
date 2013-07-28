package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a data structure for interacting with LDAP URLs.  It may
 * be used to encode and decode URLs, as well as access the various elements
 * that they contain.  Note that this implementation currently does not support
 * the use of extensions in an LDAP URL.
 * <BR><BR>
 * The components that may be included in an LDAP URL include:
 * <UL>
 *   <LI>Scheme -- This specifies the protocol to use when communicating with
 *       the server.  The official LDAP URL specification only allows a scheme
 *       of "{@code ldap}", but this implementation also supports the use of the
 *       "{@code ldaps}" scheme to indicate that clients should attempt to
 *       perform SSL-based communication with the target server (LDAPS) rather
 *       than unencrypted LDAP.  It will also accept "{@code ldapi}", which is
 *       LDAP over UNIX domain sockets, although the LDAP SDK does not directly
 *       support that mechanism of communication.</LI>
 *   <LI>Host -- This specifies the address of the directory server to which the
 *       URL refers.  If no host is provided, then it is expected that the
 *       client has some prior knowledge of the host (it often implies the same
 *       server from which the URL was retrieved).</LI>
 *   <LI>Port -- This specifies the port of the directory server to which the
 *       URL refers.  If no host or port is provided, then it is assumed that
 *       the client has some prior knowledge of the instance to use (it often
 *       implies the same instance from which the URL was retrieved).  If a host
 *       is provided without a port, then it should be assumed that the standard
 *       LDAP port of 389 should be used (or the standard LDAPS port of 636 if
 *       the scheme is "{@code ldaps}", or a value of 0 if the scheme is
 *       "{@code ldapi}").</LI>
 *   <LI>Base DN -- This specifies the base DN for the URL.  If no base DN is
 *       provided, then a default of the null DN should be assumed.</LI>
 *   <LI>Requested attributes -- This specifies the set of requested attributes
 *       for the URL.  If no attributes are specified, then the behavior should
 *       be the same as if no attributes had been provided for a search request
 *       (i.e., all user attributes should be included).
 *       <BR><BR>
 *       In the string representation of an LDAP URL, the names of the requested
 *       attributes (if more than one is provided) should be separated by
 *       commas.</LI>
 *   <LI>Scope -- This specifies the scope for the URL.  It should be one of the
 *       standard scope values as defined in the {@link SearchRequest}
 *       class.  If no scope is provided, then it should be assumed that a
 *       scope of {@link SearchScope#BASE} should be used.
 *       <BR><BR>
 *       In the string representation, the names of the scope values that are
 *       allowed include:
 *       <UL>
 *         <LI>base -- Equivalent to {@link SearchScope#BASE}.</LI>
 *         <LI>one -- Equivalent to {@link SearchScope#ONE}.</LI>
 *         <LI>sub -- Equivalent to {@link SearchScope#SUB}.</LI>
 *         <LI>subordinates -- Equivalent to
 *             {@link SearchScope#SUBORDINATE_SUBTREE}.</LI>
 *       </UL></LI>
 *   <LI>Filter -- This specifies the filter for the URL.  If no filter is
 *       provided, then a default of "{@code (objectClass=*)}" should be
 *       assumed.</LI>
 * </UL>
 * An LDAP URL encapsulates many of the properties of a search request, and in
 * fact the {@link com.hwlcn.ldap.ldap.sdk.LDAPURL#toSearchRequest} method may be used  to create a
 * {@link SearchRequest} object from an LDAP URL.
 * <BR><BR>
 * See <A HREF="http://www.ietf.org/rfc/rfc4516.txt">RFC 4516</A> for a complete
 * description of the LDAP URL syntax.  Some examples of LDAP URLs include:
 * <UL>
 *   <LI>{@code ldap://} -- This is the smallest possible LDAP URL that can be
 *       represented.  The default values will be used for all components other
 *       than the scheme.</LI>
 *   <LI>{@code
 *        ldap://server.example.com:1234/dc=example,dc=com?cn,sn?sub?(uid=john)}
 *       -- This is an example of a URL containing all of the elements.  The
 *       scheme is "{@code ldap}", the host is "{@code server.example.com}",
 *       the port is "{@code 1234}", the base DN is "{@code dc=example,dc=com}",
 *       the requested attributes are "{@code cn}" and "{@code sn}", the scope
 *       is "{@code sub}" (which indicates a subtree scope equivalent to
 *       {@link SearchScope#SUB}), and a filter of
 *       "{@code (uid=john)}".</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPURL
       implements Serializable
{

  private static final Filter DEFAULT_FILTER =
       Filter.createPresenceFilter("objectClass");

  public static final int DEFAULT_LDAP_PORT = 389;


  public static final int DEFAULT_LDAPS_PORT = 636;


  public static final int DEFAULT_LDAPI_PORT = 0;


  private static final SearchScope DEFAULT_SCOPE = SearchScope.BASE;



  private static final DN DEFAULT_BASE_DN = DN.NULL_DN;


  private static final String[] DEFAULT_ATTRIBUTES = NO_STRINGS;


  private static final long serialVersionUID = 3420786933570240493L;


 private final boolean attributesProvided;

  private final boolean baseDNProvided;

  private final boolean filterProvided;

  private final boolean portProvided;

  private final boolean scopeProvided;

  private final DN baseDN;

  private final Filter filter;

  private final int port;

  private final SearchScope scope;

  private final String host;

  private volatile String normalizedURLString;

  private final String scheme;

  private final String urlString;

  private final String[] attributes;


  public LDAPURL(final String urlString)
         throws LDAPException
  {
    ensureNotNull(urlString);

    this.urlString = urlString;

    final int colonPos = urlString.indexOf("://");
    if (colonPos < 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_NO_COLON_SLASHES.get());
    }

    scheme = toLowerCase(urlString.substring(0, colonPos));
    final int defaultPort;
    if (scheme.equals("ldap"))
    {
      defaultPort = DEFAULT_LDAP_PORT;
    }
    else if (scheme.equals("ldaps"))
    {
      defaultPort = DEFAULT_LDAPS_PORT;
    }
    else if (scheme.equals("ldapi"))
    {
      defaultPort = DEFAULT_LDAPI_PORT;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCHEME.get(scheme));
    }


    final int slashPos = urlString.indexOf('/', colonPos+3);
    if (slashPos < 0)
    {

      baseDN             = DEFAULT_BASE_DN;
      baseDNProvided     = false;
      attributes         = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
      scope              = DEFAULT_SCOPE;
      scopeProvided      = false;
      filter             = DEFAULT_FILTER;
      filterProvided     = false;

      final String hostPort = urlString.substring(colonPos+3);
      final StringBuilder hostBuffer = new StringBuilder(hostPort.length());
      final int portValue = decodeHostPort(hostPort, hostBuffer);
      if (portValue < 0)
      {
        port         = defaultPort;
        portProvided = false;
      }
      else
      {
        port         = portValue;
        portProvided = true;
      }

      if (hostBuffer.length() == 0)
      {
        host = null;
      }
      else
      {
        host = hostBuffer.toString();
      }
      return;
    }

    final String hostPort = urlString.substring(colonPos+3, slashPos);
    final StringBuilder hostBuffer = new StringBuilder(hostPort.length());
    final int portValue = decodeHostPort(hostPort, hostBuffer);
    if (portValue < 0)
    {
      port         = defaultPort;
      portProvided = false;
    }
    else
    {
      port         = portValue;
      portProvided = true;
    }

    if (hostBuffer.length() == 0)
    {
      host = null;
    }
    else
    {
      host = hostBuffer.toString();
    }

    final int questionMarkPos = urlString.indexOf('?', slashPos+1);
    if (questionMarkPos < 0)
    {
      attributes         = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
      scope              = DEFAULT_SCOPE;
      scopeProvided      = false;
      filter             = DEFAULT_FILTER;
      filterProvided     = false;

      baseDN = new DN(percentDecode(urlString.substring(slashPos+1)));
      baseDNProvided = (! baseDN.isNullDN());
      return;
    }

    baseDN = new DN(percentDecode(urlString.substring(slashPos+1,
                                                      questionMarkPos)));
    baseDNProvided = (! baseDN.isNullDN());


    final int questionMark2Pos = urlString.indexOf('?', questionMarkPos+1);
    if (questionMark2Pos < 0)
    {
      scope          = DEFAULT_SCOPE;
      scopeProvided  = false;
      filter         = DEFAULT_FILTER;
      filterProvided = false;

      attributes = decodeAttributes(urlString.substring(questionMarkPos+1));
      attributesProvided = (attributes.length > 0);
      return;
    }

    attributes = decodeAttributes(urlString.substring(questionMarkPos+1,
                                                      questionMark2Pos));
    attributesProvided = (attributes.length > 0);


    final int questionMark3Pos = urlString.indexOf('?', questionMark2Pos+1);
    if (questionMark3Pos < 0)
    {
      filter         = DEFAULT_FILTER;
      filterProvided = false;

      final String scopeStr =
           toLowerCase(urlString.substring(questionMark2Pos+1));
      if (scopeStr.length() == 0)
      {
        scope         = SearchScope.BASE;
        scopeProvided = false;
      }
      else if (scopeStr.equals("base"))
      {
        scope         = SearchScope.BASE;
        scopeProvided = true;
      }
      else if (scopeStr.equals("one"))
      {
        scope         = SearchScope.ONE;
        scopeProvided = true;
      }
      else if (scopeStr.equals("sub"))
      {
        scope         = SearchScope.SUB;
        scopeProvided = true;
      }
      else if (scopeStr.equals("subord") || scopeStr.equals("subordinates"))
      {
        scope         = SearchScope.SUBORDINATE_SUBTREE;
        scopeProvided = true;
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_INVALID_SCOPE.get(scopeStr));
      }
      return;
    }

    final String scopeStr =
         toLowerCase(urlString.substring(questionMark2Pos+1, questionMark3Pos));
    if (scopeStr.length() == 0)
    {
      scope         = SearchScope.BASE;
      scopeProvided = false;
    }
    else if (scopeStr.equals("base"))
    {
      scope         = SearchScope.BASE;
      scopeProvided = true;
    }
    else if (scopeStr.equals("one"))
    {
      scope         = SearchScope.ONE;
      scopeProvided = true;
    }
    else if (scopeStr.equals("sub"))
    {
      scope         = SearchScope.SUB;
      scopeProvided = true;
    }
        else if (scopeStr.equals("subord") || scopeStr.equals("subordinates"))
    {
      scope         = SearchScope.SUBORDINATE_SUBTREE;
      scopeProvided = true;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCOPE.get(scopeStr));
    }

    final String filterStr =
         percentDecode(urlString.substring(questionMark3Pos+1));
    if (filterStr.length() == 0)
    {
      filter = DEFAULT_FILTER;
      filterProvided = false;
    }
    else
    {
      filter = Filter.create(filterStr);
      filterProvided = true;
    }
  }


  public LDAPURL(final String scheme, final String host, final Integer port,
                 final DN baseDN, final String[] attributes,
                 final SearchScope scope, final Filter filter)
         throws LDAPException
  {
    ensureNotNull(scheme);

    final StringBuilder buffer = new StringBuilder();

    this.scheme = toLowerCase(scheme);
    final int defaultPort;
    if (scheme.equals("ldap"))
    {
      defaultPort = DEFAULT_LDAP_PORT;
    }
    else if (scheme.equals("ldaps"))
    {
      defaultPort = DEFAULT_LDAPS_PORT;
    }
    else if (scheme.equals("ldapi"))
    {
      defaultPort = DEFAULT_LDAPI_PORT;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_LDAPURL_INVALID_SCHEME.get(scheme));
    }

    buffer.append(scheme);
    buffer.append("://");

    if ((host == null) || (host.length() == 0))
    {
      this.host = null;
    }
    else
    {
      this.host = host;
      buffer.append(host);
    }

    if (port == null)
    {
      this.port = defaultPort;
      portProvided = false;
    }
    else
    {
      this.port = port;
      portProvided = true;
      buffer.append(':');
      buffer.append(port);

      if ((port < 1) || (port > 65535))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
                                ERR_LDAPURL_INVALID_PORT.get(port));
      }
    }

    buffer.append('/');
    if (baseDN == null)
    {
      this.baseDN = DEFAULT_BASE_DN;
      baseDNProvided = false;
    }
    else
    {
      this.baseDN = baseDN;
      baseDNProvided = true;
      percentEncode(baseDN.toString(), buffer);
    }

    final boolean continueAppending;
    if (((attributes == null) || (attributes.length == 0)) && (scope == null) &&
        (filter == null))
    {
      continueAppending = false;
    }
    else
    {
      continueAppending = true;
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if ((attributes == null) || (attributes.length == 0))
    {
      this.attributes = DEFAULT_ATTRIBUTES;
      attributesProvided = false;
    }
    else
    {
      this.attributes = attributes;
      attributesProvided = true;

      for (int i=0; i < attributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(',');
        }
        buffer.append(attributes[i]);
      }
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if (scope == null)
    {
      this.scope = DEFAULT_SCOPE;
      scopeProvided = false;
    }
    else
    {
      switch (scope.intValue())
      {
        case 0:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("base");
          break;
        case 1:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("one");
          break;
        case 2:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("sub");
          break;
        case 3:
          this.scope = scope;
          scopeProvided = true;
          buffer.append("subordinates");
          break;
        default:
          throw new LDAPException(ResultCode.PARAM_ERROR,
                                  ERR_LDAPURL_INVALID_SCOPE_VALUE.get(scope));
      }
    }

    if (continueAppending)
    {
      buffer.append('?');
    }
    if (filter == null)
    {
      this.filter = DEFAULT_FILTER;
      filterProvided = false;
    }
    else
    {
      this.filter = filter;
      filterProvided = true;
      percentEncode(filter.toString(), buffer);
    }

    urlString = buffer.toString();
  }

  private static int decodeHostPort(final String hostPort,
                                    final StringBuilder hostBuffer)
          throws LDAPException
  {
    final int length = hostPort.length();
    if (length == 0)
    {
      return -1;
    }

    if (hostPort.charAt(0) == '[')
    {
      final int closingBracketPos = hostPort.indexOf(']');
      if (closingBracketPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_IPV6_HOST_MISSING_BRACKET.get());
      }

      hostBuffer.append(hostPort.substring(1, closingBracketPos).trim());
      if (hostBuffer.length() == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_IPV6_HOST_EMPTY.get());
      }

      if (closingBracketPos == (length - 1))
      {
        return -1;
      }
      else
      {
        if (hostPort.charAt(closingBracketPos+1) != ':')
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_IPV6_HOST_UNEXPECTED_CHAR.get(
                                       hostPort.charAt(closingBracketPos+1)));
        }
        else
        {
          try
          {
            final int decodedPort =
                 Integer.parseInt(hostPort.substring(closingBracketPos+2));
            if ((decodedPort >= 1) && (decodedPort <= 65535))
            {
              return decodedPort;
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_LDAPURL_INVALID_PORT.get(
                                           decodedPort));
            }
          }
          catch (NumberFormatException nfe)
          {
            debugException(nfe);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_PORT_NOT_INT.get(hostPort),
                                    nfe);
          }
        }
      }
    }

    final int colonPos = hostPort.indexOf(':');
    if (colonPos < 0)
    {
      hostBuffer.append(hostPort);
      return -1;
    }
    else
    {
      try
      {
        final int decodedPort =
             Integer.parseInt(hostPort.substring(colonPos+1));
        if ((decodedPort >= 1) && (decodedPort <= 65535))
        {
          hostBuffer.append(hostPort.substring(0, colonPos));
          return decodedPort;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_INVALID_PORT.get(decodedPort));
        }
      }
      catch (NumberFormatException nfe)
      {
        debugException(nfe);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_LDAPURL_PORT_NOT_INT.get(hostPort), nfe);
      }
    }
  }

  private static String[] decodeAttributes(final String s)
          throws LDAPException
  {
    final int length = s.length();
    if (length == 0)
    {
      return DEFAULT_ATTRIBUTES;
    }

    final ArrayList<String> attrList = new ArrayList<String>();
    int startPos = 0;
    while (startPos < length)
    {
      final int commaPos = s.indexOf(',', startPos);
      if (commaPos < 0)
      {
        final String attrName = s.substring(startPos).trim();
        if (attrName.length() == 0)
        {
          if (attrList.isEmpty())
          {
            return DEFAULT_ATTRIBUTES;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_ATTRLIST_ENDS_WITH_COMMA.get());
          }
        }
        else
        {
          attrList.add(attrName);
          break;
        }
      }
      else
      {
        final String attrName = s.substring(startPos, commaPos).trim();
        if (attrName.length() == 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_ATTRLIST_EMPTY_ATTRIBUTE.get());
        }
        else
        {
          attrList.add(attrName);
          startPos = commaPos+1;
          if (startPos >= length)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_ATTRLIST_ENDS_WITH_COMMA.get());
          }
        }
      }
    }

    final String[] attributes = new String[attrList.size()];
    attrList.toArray(attributes);
    return attributes;
  }


  public static String percentDecode(final String s)
          throws LDAPException
  {
    int firstPercentPos = -1;
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      if (s.charAt(i) == '%')
      {
        firstPercentPos = i;
        break;
      }
    }

    if (firstPercentPos < 0)
    {
      return s;
    }

    int pos = firstPercentPos;
    final StringBuilder buffer = new StringBuilder(2 * length);
    buffer.append(s.substring(0, firstPercentPos));

    while (pos < length)
    {
      final char c = s.charAt(pos++);
      if (c == '%')
      {
        if (pos >= length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_LDAPURL_HEX_STRING_TOO_SHORT.get(s));
        }


        final ByteBuffer byteBuffer = ByteBuffer.allocate(length - pos);
        while (pos < length)
        {
          byte b;
          switch (s.charAt(pos++))
          {
            case '0':
              b = 0x00;
              break;
            case '1':
              b = 0x10;
              break;
            case '2':
              b = 0x20;
              break;
            case '3':
              b = 0x30;
              break;
            case '4':
              b = 0x40;
              break;
            case '5':
              b = 0x50;
              break;
            case '6':
              b = 0x60;
              break;
            case '7':
              b = 0x70;
              break;
            case '8':
              b = (byte) 0x80;
              break;
            case '9':
              b = (byte) 0x90;
              break;
            case 'a':
            case 'A':
              b = (byte) 0xA0;
              break;
            case 'b':
            case 'B':
              b = (byte) 0xB0;
              break;
            case 'c':
            case 'C':
              b = (byte) 0xC0;
              break;
            case 'd':
            case 'D':
              b = (byte) 0xD0;
              break;
            case 'e':
            case 'E':
              b = (byte) 0xE0;
              break;
            case 'f':
            case 'F':
              b = (byte) 0xF0;
              break;
            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_LDAPURL_INVALID_HEX_CHAR.get(
                                           s.charAt(pos-1)));
          }

          if (pos >= length)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_LDAPURL_HEX_STRING_TOO_SHORT.get(s));
          }

          switch (s.charAt(pos++))
          {
            case '0':
              b |= 0x00;
              break;
            case '1':
              b |= 0x01;
              break;
            case '2':
              b |= 0x02;
              break;
            case '3':
              b |= 0x03;
              break;
            case '4':
              b |= 0x04;
              break;
            case '5':
              b |= 0x05;
              break;
            case '6':
              b |= 0x06;
              break;
            case '7':
              b |= 0x07;
              break;
            case '8':
              b |= 0x08;
              break;
            case '9':
              b |= 0x09;
              break;
            case 'a':
            case 'A':
              b |= 0x0A;
              break;
            case 'b':
            case 'B':
              b |= 0x0B;
              break;
            case 'c':
            case 'C':
              b |= 0x0C;
              break;
            case 'd':
            case 'D':
              b |= 0x0D;
              break;
            case 'e':
            case 'E':
              b |= 0x0E;
              break;
            case 'f':
            case 'F':
              b |= 0x0F;
              break;
            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_LDAPURL_INVALID_HEX_CHAR.get(
                                           s.charAt(pos-1)));
          }

          byteBuffer.put(b);
          if ((pos < length) && (s.charAt(pos) != '%'))
          {
            break;
          }
        }

        byteBuffer.flip();
        final byte[] byteArray = new byte[byteBuffer.limit()];
        byteBuffer.get(byteArray);

        buffer.append(toUTF8String(byteArray));
      }
      else
      {
        buffer.append(c);
      }
    }

    return buffer.toString();
  }

  private static void percentEncode(final String s, final StringBuilder buffer)
  {
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);

      switch (c)
      {
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'G':
        case 'H':
        case 'I':
        case 'J':
        case 'K':
        case 'L':
        case 'M':
        case 'N':
        case 'O':
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'T':
        case 'U':
        case 'V':
        case 'W':
        case 'X':
        case 'Y':
        case 'Z':
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'g':
        case 'h':
        case 'i':
        case 'j':
        case 'k':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'u':
        case 'v':
        case 'w':
        case 'x':
        case 'y':
        case 'z':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '-':
        case '.':
        case '_':
        case '~':
        case '!':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
          buffer.append(c);
          break;

        default:
          final byte[] charBytes = getBytes(new String(new char[] { c }));
          for (final byte b : charBytes)
          {
            buffer.append('%');
            toHex(b, buffer);
          }
          break;
      }
    }
  }


  public String getScheme()
  {
    return scheme;
  }

  public String getHost()
  {
    return host;
  }


  public boolean hostProvided()
  {
    return (host != null);
  }


  public int getPort()
  {
    return port;
  }

  public boolean portProvided()
  {
    return portProvided;
  }


  public DN getBaseDN()
  {
    return baseDN;
  }

  public boolean baseDNProvided()
  {
    return baseDNProvided;
  }

  public String[] getAttributes()
  {
    return attributes;
  }

  public boolean attributesProvided()
  {
    return attributesProvided;
  }

  public SearchScope getScope()
  {
    return scope;
  }


  public boolean scopeProvided()
  {
    return scopeProvided;
  }

  public Filter getFilter()
  {
    return filter;
  }

  public boolean filterProvided()
  {
    return filterProvided;
  }


  public SearchRequest toSearchRequest()
  {
    return new SearchRequest(baseDN.toString(), scope, filter, attributes);
  }


  @Override()
  public int hashCode()
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

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDAPURL))
    {
      return false;
    }

    final LDAPURL url = (LDAPURL) o;
    return toNormalizedString().equals(url.toNormalizedString());
  }


  @Override()
  public String toString()
  {
    return urlString;
  }

  public String toNormalizedString()
  {
    if (normalizedURLString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedURLString = buffer.toString();
    }

    return normalizedURLString;
  }


  public void toNormalizedString(final StringBuilder buffer)
  {
    buffer.append(scheme);
    buffer.append("://");

    if (host != null)
    {
      if (host.indexOf(':') >= 0)
      {
        buffer.append('[');
        buffer.append(toLowerCase(host));
        buffer.append(']');
      }
      else
      {
        buffer.append(toLowerCase(host));
      }
    }

    if (! scheme.equals("ldapi"))
    {
      buffer.append(':');
      buffer.append(port);
    }

    buffer.append('/');
    percentEncode(baseDN.toNormalizedString(), buffer);
    buffer.append('?');

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(toLowerCase(attributes[i]));
    }

    buffer.append('?');
    switch (scope.intValue())
    {
      case 0:
        buffer.append("base");
        break;
      case 1:
        buffer.append("one");
        break;
      case 2:
        buffer.append("sub");
        break;
      case 3:
        buffer.append("subordinates");
        break;
    }

    buffer.append('?');
    percentEncode(filter.toNormalizedString(), buffer);
  }
}
