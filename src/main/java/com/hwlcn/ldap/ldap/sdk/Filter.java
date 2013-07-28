package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1BufferSet;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1Set;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSet;
import com.hwlcn.ldap.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a data structure that represents an LDAP search filter.
 * It provides methods for creating various types of filters, as well as parsing
 * a filter from a string.  See
 * <A HREF="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</A> for more
 * information about representing search filters as strings.
 * <BR><BR>
 * The following filter types are defined:
 * <UL>
 *   <LI><B>AND</B> -- This is used to indicate that a filter should match an
 *       entry only if all of the embedded filter components match that entry.
 *       An AND filter with zero embedded filter components is considered an
 *       LDAP TRUE filter as defined in
 *       <A HREF="http://www.ietf.org/rfc/rfc4526.txt">RFC 4526</A> and will
 *       match any entry.  AND filters contain only a set of embedded filter
 *       components, and each of those embedded components can itself be any
 *       type of filter, including an AND, OR, or NOT filter with additional
 *       embedded components.</LI>
 *   <LI><B>OR</B> -- This is used to indicate that a filter should match an
 *       entry only if at least one of the embedded filter components matches
 *       that entry.   An OR filter with zero embedded filter components is
 *       considered an LDAP FALSE filter as defined in
 *       <A HREF="http://www.ietf.org/rfc/rfc4526.txt">RFC 4526</A> and will
 *       never match any entry.  OR filters contain only a set of embedded
 *       filter components, and each of those embedded components can itself be
 *       any type of filter, including an AND, OR, or NOT filter with additional
 *       embedded components.</LI>
 *   <LI><B>NOT</B> -- This is used to indicate that a filter should match an
 *       entry only if the embedded NOT component does not match the entry.  A
 *       NOT filter contains only a single embedded NOT filter component, but
 *       that embedded component can itself be any type of filter, including an
 *       AND, OR, or NOT filter with additional embedded components.</LI>
 *   <LI><B>EQUALITY</B> -- This is used to indicate that a filter should match
 *       an entry only if the entry contains a value for the specified attribute
 *       that is equal to the provided assertion value.  An equality filter
 *       contains only an attribute name and an assertion value.</LI>
 *   <LI><B>SUBSTRING</B> -- This is used to indicate that a filter should match
 *       an entry only if the entry contains at least one value for the
 *       specified attribute that matches the provided substring assertion.  The
 *       substring assertion must contain at least one element of the following
 *       types:
 *       <UL>
 *         <LI>subInitial -- This indicates that the specified string must
 *             appear at the beginning of the attribute value.  There can be at
 *             most one subInitial element in a substring assertion.</LI>
 *         <LI>subAny -- This indicates that the specified string may appear
 *             anywhere in the attribute value.  There can be any number of
 *             substring subAny elements in a substring assertion.  If there are
 *             multiple subAny elements, then they must match in the order that
 *             they are provided.</LI>
 *         <LI>subFinal -- This indicates that the specified string must appear
 *             at the end of the attribute value.  There can be at most one
 *             subFinal element in a substring assertion.</LI>
 *       </UL>
 *       A substring filter contains only an attribute name and subInitial,
 *       subAny, and subFinal elements.</LI>
 *   <LI><B>GREATER-OR-EQUAL</B> -- This is used to indicate that a filter
 *       should match an entry only if that entry contains at least one value
 *       for the specified attribute that is greater than or equal to the
 *       provided assertion value.  A greater-or-equal filter contains only an
 *       attribute name and an assertion value.</LI>
 *   <LI><B>LESS-OR-EQUAL</B> -- This is used to indicate that a filter should
 *       match an entry only if that entry contains at least one value for the
 *       specified attribute that is less than or equal to the provided
 *       assertion value.  A less-or-equal filter contains only an attribute
 *       name and an assertion value.</LI>
 *   <LI><B>PRESENCE</B> -- This is used to indicate that a filter should match
 *       an entry only if the entry contains at least one value for the
 *       specified attribute.  A presence filter contains only an attribute
 *       name.</LI>
 *   <LI><B>APPROXIMATE-MATCH</B> -- This is used to indicate that a filter
 *       should match an entry only if the entry contains at least one value for
 *       the specified attribute that is approximately equal to the provided
 *       assertion value.  The definition of "approximately equal to" may vary
 *       from one server to another, and from one attribute to another, but it
 *       is often implemented as a "sounds like" match using a variant of the
 *       metaphone or double-metaphone algorithm.  An approximate-match filter
 *       contains only an attribute name and an assertion value.</LI>
 *   <LI><B>EXTENSIBLE-MATCH</B> -- This is used to perform advanced types of
 *       matching against entries, according to the following criteria:
 *       <UL>
 *         <LI>If an attribute name is provided, then the assertion value must
 *             match one of the values for that attribute (potentially including
 *             values contained in the entry's DN).  If a matching rule ID is
 *             also provided, then the associated matching rule will be used to
 *             determine whether there is a match; otherwise the default
 *             equality matching rule for that attribute will be used.</LI>
 *         <LI>If no attribute name is provided, then a matching rule ID must be
 *             given, and the corresponding matching rule will be used to
 *             determine whether any attribute in the target entry (potentially
 *             including attributes contained in the entry's DN) has at least
 *             one value that matches the provided assertion value.</LI>
 *         <LI>If the dnAttributes flag is set, then attributes contained in the
 *             entry's DN will also be evaluated to determine if they match the
 *             filter criteria.  If it is not set, then attributes contained in
 *             the entry's DN (other than those contained in its RDN which are
 *             also present as separate attributes in the entry) will not be
*             examined.</LI>
 *       </UL>
 *       An extensible match filter contains only an attribute name, matching
 *       rule ID, dnAttributes flag, and an assertion value.</LI>
 * </UL>
 * <BR><BR>
 * There are two primary ways to create a search filter.  The first is to create
 * a filter from its string representation with the
 * {@link com.hwlcn.ldap.ldap.sdk.Filter#create(String)} method, using the syntax described in RFC 4515.
 * For example:
 * <PRE>
 *   Filter f1 = Filter.create("(objectClass=*)");
 *   Filter f2 = Filter.create("(uid=john.doe)");
 *   Filter f3 = Filter.create("(|(givenName=John)(givenName=Johnathan))");
 * </PRE>
 * <BR><BR>
 * Creating a filter from its string representation is a common approach and
 * seems to be relatively straightforward, but it does have some hidden dangers.
 * This primarily comes from the potential for special characters in the filter
 * string which need to be properly escaped.  If this isn't done, then the
 * search may fail or behave unexpectedly, or worse it could lead to a
 * vulnerability in the application in which a malicious user could trick the
 * application into retrieving more information than it should have.  To avoid
 * these problems, it may be better to construct filters from their individual
 * components rather than their string representations, like:
 * <PRE>
 *   Filter f1 = Filter.createPresenceFilter("objectClass");
 *   Filter f2 = Filter.createEqualityFilter("uid", "john.doe");
 *   Filter f3 = Filter.createORFilter(
 *                    Filter.createEqualityFilter("givenName", "John"),
 *                    Filter.createEqualityFilter("givenName", "Johnathan"));
 * </PRE>
 * In general, it is recommended to avoid creating filters from their string
 * representations if any of that string representation may include
 * user-provided data or special characters including non-ASCII characters,
 * parentheses, asterisks, or backslashes.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Filter
       implements Serializable
{
  public static final byte FILTER_TYPE_AND = (byte) 0xA0;

 public static final byte FILTER_TYPE_OR = (byte) 0xA1;

  public static final byte FILTER_TYPE_NOT = (byte) 0xA2;


  public static final byte FILTER_TYPE_EQUALITY = (byte) 0xA3;


  public static final byte FILTER_TYPE_SUBSTRING = (byte) 0xA4;


  public static final byte FILTER_TYPE_GREATER_OR_EQUAL = (byte) 0xA5;


  public static final byte FILTER_TYPE_LESS_OR_EQUAL = (byte) 0xA6;


  public static final byte FILTER_TYPE_PRESENCE = (byte) 0x87;


  public static final byte FILTER_TYPE_APPROXIMATE_MATCH = (byte) 0xA8;


  public static final byte FILTER_TYPE_EXTENSIBLE_MATCH = (byte) 0xA9;

  private static final byte SUBSTRING_TYPE_SUBINITIAL = (byte) 0x80;

  private static final byte SUBSTRING_TYPE_SUBANY = (byte) 0x81;


  private static final byte SUBSTRING_TYPE_SUBFINAL = (byte) 0x82;

  private static final byte EXTENSIBLE_TYPE_MATCHING_RULE_ID = (byte) 0x81;

  private static final byte EXTENSIBLE_TYPE_ATTRIBUTE_NAME = (byte) 0x82;

  private static final byte EXTENSIBLE_TYPE_MATCH_VALUE = (byte) 0x83;

  private static final byte EXTENSIBLE_TYPE_DN_ATTRIBUTES = (byte) 0x84;

  private static final Filter[] NO_FILTERS = new Filter[0];

  private static final ASN1OctetString[] NO_SUB_ANY = new ASN1OctetString[0];

  private static final long serialVersionUID = -2734184402804691970L;

  private final ASN1OctetString assertionValue;

  private final ASN1OctetString subFinal;

  private final ASN1OctetString subInitial;

  private final ASN1OctetString[] subAny;

  private final boolean dnAttributes;

  private final Filter notComp;

  private final Filter[] filterComps;

  private final byte filterType;

  private final String attrName;

  private volatile String filterString;

  private final String matchingRuleID;

  private volatile String normalizedString;


 private Filter(final String filterString, final byte filterType,
                 final Filter[] filterComps, final Filter notComp,
                 final String attrName, final ASN1OctetString assertionValue,
                 final ASN1OctetString subInitial,
                 final ASN1OctetString[] subAny, final ASN1OctetString subFinal,
                 final String matchingRuleID, final boolean dnAttributes)
  {
    this.filterString   = filterString;
    this.filterType     = filterType;
    this.filterComps    = filterComps;
    this.notComp        = notComp;
    this.attrName       = attrName;
    this.assertionValue = assertionValue;
    this.subInitial     = subInitial;
    this.subAny         = subAny;
    this.subFinal       = subFinal;
    this.matchingRuleID = matchingRuleID;
    this.dnAttributes  = dnAttributes;
  }



  public static Filter createANDFilter(final Filter... andComponents)
  {
    ensureNotNull(andComponents);

    return new Filter(null, FILTER_TYPE_AND, andComponents, null, null, null,
                      null, NO_SUB_ANY, null, null, false);
  }



  public static Filter createANDFilter(final List<Filter> andComponents)
  {
    ensureNotNull(andComponents);

    return new Filter(null, FILTER_TYPE_AND,
                      andComponents.toArray(new Filter[andComponents.size()]),
                      null, null, null, null, NO_SUB_ANY, null, null, false);
  }



  public static Filter createORFilter(final Filter... orComponents)
  {
    ensureNotNull(orComponents);

    return new Filter(null, FILTER_TYPE_OR, orComponents, null, null, null,
                      null, NO_SUB_ANY, null, null, false);
  }



  public static Filter createORFilter(final List<Filter> orComponents)
  {
    ensureNotNull(orComponents);

    return new Filter(null, FILTER_TYPE_OR,
                      orComponents.toArray(new Filter[orComponents.size()]),
                      null, null, null, null, NO_SUB_ANY, null, null, false);
  }



  public static Filter createNOTFilter(final Filter notComponent)
  {
    ensureNotNull(notComponent);

    return new Filter(null, FILTER_TYPE_NOT, NO_FILTERS, notComponent, null,
                      null, null, NO_SUB_ANY, null, null, false);
  }



  public static Filter createEqualityFilter(final String attributeName,
                                            final String assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_EQUALITY, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }



  public static Filter createEqualityFilter(final String attributeName,
                                            final byte[] assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_EQUALITY, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }



  static Filter createEqualityFilter(final String attributeName,
                                     final ASN1OctetString assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_EQUALITY, NO_FILTERS, null,
                      attributeName, assertionValue, null, NO_SUB_ANY, null,
                      null, false);
  }


  public static Filter createSubstringFilter(final String attributeName,
                                             final String subInitial,
                                             final String[] subAny,
                                             final String subFinal)
  {
    ensureNotNull(attributeName);
    ensureTrue((subInitial != null) ||
               ((subAny != null) && (subAny.length > 0)) ||
               (subFinal != null));

    final ASN1OctetString subInitialOS;
    if (subInitial == null)
    {
      subInitialOS = null;
    }
    else
    {
      subInitialOS = new ASN1OctetString(subInitial);
    }

    final ASN1OctetString[] subAnyArray;
    if (subAny == null)
    {
      subAnyArray = NO_SUB_ANY;
    }
    else
    {
      subAnyArray = new ASN1OctetString[subAny.length];
      for (int i=0; i < subAny.length; i++)
      {
        subAnyArray[i] = new ASN1OctetString(subAny[i]);
      }
    }

    final ASN1OctetString subFinalOS;
    if (subFinal == null)
    {
      subFinalOS = null;
    }
    else
    {
      subFinalOS = new ASN1OctetString(subFinal);
    }

    return new Filter(null, FILTER_TYPE_SUBSTRING, NO_FILTERS, null,
                      attributeName, null, subInitialOS, subAnyArray,
                      subFinalOS, null, false);
  }


  public static Filter createSubstringFilter(final String attributeName,
                                             final byte[] subInitial,
                                             final byte[][] subAny,
                                             final byte[] subFinal)
  {
    ensureNotNull(attributeName);
    ensureTrue((subInitial != null) ||
               ((subAny != null) && (subAny.length > 0)) ||
               (subFinal != null));

    final ASN1OctetString subInitialOS;
    if (subInitial == null)
    {
      subInitialOS = null;
    }
    else
    {
      subInitialOS = new ASN1OctetString(subInitial);
    }

    final ASN1OctetString[] subAnyArray;
    if (subAny == null)
    {
      subAnyArray = NO_SUB_ANY;
    }
    else
    {
      subAnyArray = new ASN1OctetString[subAny.length];
      for (int i=0; i < subAny.length; i++)
      {
        subAnyArray[i] = new ASN1OctetString(subAny[i]);
      }
    }

    final ASN1OctetString subFinalOS;
    if (subFinal == null)
    {
      subFinalOS = null;
    }
    else
    {
      subFinalOS = new ASN1OctetString(subFinal);
    }

    return new Filter(null, FILTER_TYPE_SUBSTRING, NO_FILTERS, null,
                      attributeName, null, subInitialOS, subAnyArray,
                      subFinalOS, null, false);
  }

  static Filter createSubstringFilter(final String attributeName,
                                      final ASN1OctetString subInitial,
                                      final ASN1OctetString[] subAny,
                                      final ASN1OctetString subFinal)
  {
    ensureNotNull(attributeName);
    ensureTrue((subInitial != null) ||
               ((subAny != null) && (subAny.length > 0)) ||
               (subFinal != null));

    if (subAny == null)
    {
      return new Filter(null, FILTER_TYPE_SUBSTRING, NO_FILTERS, null,
                        attributeName, null, subInitial, NO_SUB_ANY, subFinal,
                        null, false);
    }
    else
    {
      return new Filter(null, FILTER_TYPE_SUBSTRING, NO_FILTERS, null,
                        attributeName, null, subInitial, subAny, subFinal, null,
                        false);
    }
  }

  public static Filter createGreaterOrEqualFilter(final String attributeName,
                                                  final String assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_GREATER_OR_EQUAL, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }


  public static Filter createGreaterOrEqualFilter(final String attributeName,
                                                  final byte[] assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_GREATER_OR_EQUAL, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }



  static Filter createGreaterOrEqualFilter(final String attributeName,
                                           final ASN1OctetString assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_GREATER_OR_EQUAL, NO_FILTERS, null,
                      attributeName, assertionValue, null, NO_SUB_ANY, null,
                      null, false);
  }


  public static Filter createLessOrEqualFilter(final String attributeName,
                                               final String assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_LESS_OR_EQUAL, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }



  public static Filter createLessOrEqualFilter(final String attributeName,
                                               final byte[] assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_LESS_OR_EQUAL, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }


  static Filter createLessOrEqualFilter(final String attributeName,
                                        final ASN1OctetString assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_LESS_OR_EQUAL, NO_FILTERS, null,
                      attributeName, assertionValue, null, NO_SUB_ANY, null,
                      null, false);
  }



  public static Filter createPresenceFilter(final String attributeName)
  {
    ensureNotNull(attributeName);

    return new Filter(null, FILTER_TYPE_PRESENCE, NO_FILTERS, null,
                      attributeName, null, null, NO_SUB_ANY, null, null, false);
  }


  public static Filter createApproximateMatchFilter(final String attributeName,
                                                    final String assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_APPROXIMATE_MATCH, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }


  public static Filter createApproximateMatchFilter(final String attributeName,
                                                    final byte[] assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_APPROXIMATE_MATCH, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, null, false);
  }




  static Filter createApproximateMatchFilter(final String attributeName,
                     final ASN1OctetString assertionValue)
  {
    ensureNotNull(attributeName, assertionValue);

    return new Filter(null, FILTER_TYPE_APPROXIMATE_MATCH, NO_FILTERS, null,
                      attributeName, assertionValue, null, NO_SUB_ANY, null,
                      null, false);
  }



  public static Filter createExtensibleMatchFilter(final String attributeName,
                                                   final String matchingRuleID,
                                                   final boolean dnAttributes,
                                                   final String assertionValue)
  {
    ensureNotNull(assertionValue);
    ensureFalse((attributeName == null) && (matchingRuleID == null));

    return new Filter(null, FILTER_TYPE_EXTENSIBLE_MATCH, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, matchingRuleID, dnAttributes);
  }




  public static Filter createExtensibleMatchFilter(final String attributeName,
                                                   final String matchingRuleID,
                                                   final boolean dnAttributes,
                                                   final byte[] assertionValue)
  {
    ensureNotNull(assertionValue);
    ensureFalse((attributeName == null) && (matchingRuleID == null));

    return new Filter(null, FILTER_TYPE_EXTENSIBLE_MATCH, NO_FILTERS, null,
                      attributeName, new ASN1OctetString(assertionValue), null,
                      NO_SUB_ANY, null, matchingRuleID, dnAttributes);
  }

  static Filter createExtensibleMatchFilter(final String attributeName,
                     final String matchingRuleID, final boolean dnAttributes,
                     final ASN1OctetString assertionValue)
  {
    ensureNotNull(assertionValue);
    ensureFalse((attributeName == null) && (matchingRuleID == null));

    return new Filter(null, FILTER_TYPE_EXTENSIBLE_MATCH, NO_FILTERS, null,
                      attributeName, assertionValue, null, NO_SUB_ANY, null,
                      matchingRuleID, dnAttributes);
  }



  public static Filter create(final String filterString)
         throws LDAPException
  {
    ensureNotNull(filterString);

    return create(filterString, 0, (filterString.length() - 1), 0);
  }



  private static Filter create(final String filterString, final int startPos,
                               final int endPos, final int depth)
          throws LDAPException
  {
    if (depth > 50)
    {
      throw new LDAPException(ResultCode.FILTER_ERROR,
                              ERR_FILTER_TOO_DEEP.get());
    }

    final byte              filterType;
    final Filter[]          filterComps;
    final Filter            notComp;
    final String            attrName;
    final ASN1OctetString   assertionValue;
    final ASN1OctetString   subInitial;
    final ASN1OctetString[] subAny;
    final ASN1OctetString   subFinal;
    final String            matchingRuleID;
    final boolean           dnAttributes;

    if (startPos >= endPos)
    {
      throw new LDAPException(ResultCode.FILTER_ERROR,
                              ERR_FILTER_TOO_SHORT.get());
    }

    int l = startPos;
    int r = endPos;

    if (filterString.charAt(l) == '(')
    {
      if (filterString.charAt(r) == ')')
      {
        l++;
        r--;
      }
      else
      {
        throw new LDAPException(ResultCode.FILTER_ERROR,
                                ERR_FILTER_OPEN_WITHOUT_CLOSE.get(l, r));
      }
    }
    else
    {
      if (l != 0)
      {
        throw new LDAPException(ResultCode.FILTER_ERROR,
                                ERR_FILTER_MISSING_PARENTHESES.get(
                                    filterString.substring(l, r+1)));
      }
    }


    switch (filterString.charAt(l))
    {
      case '&':
        filterType     = FILTER_TYPE_AND;
        filterComps    = parseFilterComps(filterString, l+1, r, depth+1);
        notComp        = null;
        attrName       = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;
        break;

      case '|':
        filterType     = FILTER_TYPE_OR;
        filterComps    = parseFilterComps(filterString, l+1, r, depth+1);
        notComp        = null;
        attrName       = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;
        break;

      case '!':
        filterType     = FILTER_TYPE_NOT;
        filterComps    = NO_FILTERS;
        notComp        = create(filterString, l+1, r, depth+1);
        attrName       = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;
        break;

      case '(':
        throw new LDAPException(ResultCode.FILTER_ERROR,
                                ERR_FILTER_UNEXPECTED_OPEN_PAREN.get(l));

      case ':':
        filterType  = FILTER_TYPE_EXTENSIBLE_MATCH;
        filterComps = NO_FILTERS;
        notComp     = null;
        attrName    = null;
        subInitial  = null;
        subAny      = NO_SUB_ANY;
        subFinal    = null;

        final int dnMRIDStart = ++l;
        while ((l <= r) && (filterString.charAt(l) != ':'))
        {
          l++;
        }

        if (l > r)
        {
          throw new LDAPException(ResultCode.FILTER_ERROR,
                                  ERR_FILTER_NO_COLON_AFTER_MRID.get(
                                       startPos));
        }
        else if (l == dnMRIDStart)
        {
          throw new LDAPException(ResultCode.FILTER_ERROR,
                                  ERR_FILTER_EMPTY_MRID.get(startPos));
        }
        final String s = filterString.substring(dnMRIDStart, l++);
        if (s.equalsIgnoreCase("dn"))
        {
          dnAttributes = true;

          final int mrIDStart = l;
          while ((l < r) && (filterString.charAt(l) != ':'))
          {
            l++;
          }

          if (l >= r)
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_NO_COLON_AFTER_MRID.get(
                                         startPos));
          }

          matchingRuleID = filterString.substring(mrIDStart, l);
          if (matchingRuleID.length() == 0)
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_EMPTY_MRID.get(startPos));
          }

          if ((++l > r) || (filterString.charAt(l) != '='))
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_UNEXPECTED_CHAR_AFTER_MRID.get(
                                         filterString.charAt(l), startPos));
          }
        }
        else
        {
          matchingRuleID = s;
          dnAttributes = false;

          if ((l > r) || (filterString.charAt(l) != '='))
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_NO_EQUAL_AFTER_MRID.get(
                                         startPos));
          }
        }

        l++;
        final StringBuilder valueBuffer = new StringBuilder(r - l + 1);
        while (l <= r)
        {
          final char c = filterString.charAt(l);
          if (c == '\\')
          {
            l = readEscapedHexString(filterString, ++l, r, valueBuffer);
          }
          else if (c == '(')
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_UNEXPECTED_OPEN_PAREN.get(l));
          }
          else if (c == ')')
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_UNEXPECTED_CLOSE_PAREN.get(l));
          }
          else
          {
            valueBuffer.append(c);
            l++;
          }
        }
        assertionValue = new ASN1OctetString(valueBuffer.toString());
        break;


      default:
        filterComps = NO_FILTERS;
        notComp     = null;


        final int attrStartPos = l;
        int     attrEndPos   = -1;
        byte    tempFilterType = 0x00;
        boolean filterTypeKnown = false;
attrNameLoop:
        while (l <= r)
        {
          final char c = filterString.charAt(l++);
          switch (c)
          {
            case ':':
              tempFilterType = FILTER_TYPE_EXTENSIBLE_MATCH;
              filterTypeKnown = true;
              attrEndPos = l - 1;
              break attrNameLoop;

            case '>':
              tempFilterType = FILTER_TYPE_GREATER_OR_EQUAL;
              filterTypeKnown = true;
              attrEndPos = l - 1;

              if (l <= r)
              {
                if (filterString.charAt(l++) != '=')
                {
                  throw new LDAPException(ResultCode.FILTER_ERROR,
                                 ERR_FILTER_UNEXPECTED_CHAR_AFTER_GT.get(
                                      startPos, filterString.charAt(l-1)));
                }
              }
              else
              {
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_END_AFTER_GT.get(startPos));
              }
              break attrNameLoop;

            case '<':
              tempFilterType = FILTER_TYPE_LESS_OR_EQUAL;
              filterTypeKnown = true;
              attrEndPos = l - 1;

              if (l <= r)
              {
                if (filterString.charAt(l++) != '=')
                {
                  throw new LDAPException(ResultCode.FILTER_ERROR,
                                 ERR_FILTER_UNEXPECTED_CHAR_AFTER_LT.get(
                                      startPos, filterString.charAt(l-1)));
                }
              }
              else
              {
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_END_AFTER_LT.get(startPos));
              }
              break attrNameLoop;

            case '~':
              tempFilterType = FILTER_TYPE_APPROXIMATE_MATCH;
              filterTypeKnown = true;
              attrEndPos = l - 1;

              if (l <= r)
              {
                if (filterString.charAt(l++) != '=')
                {
                  throw new LDAPException(ResultCode.FILTER_ERROR,
                                 ERR_FILTER_UNEXPECTED_CHAR_AFTER_TILDE.get(
                                      startPos, filterString.charAt(l-1)));
                }
              }
              else
              {
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_END_AFTER_TILDE.get(
                                             startPos));
              }
              break attrNameLoop;

            case '=':
              attrEndPos = l - 1;
              break attrNameLoop;
          }
        }

        if (attrEndPos <= attrStartPos)
        {
          throw new LDAPException(ResultCode.FILTER_ERROR,
                                  ERR_FILTER_EMPTY_ATTR_NAME.get(startPos));
        }
        attrName = filterString.substring(attrStartPos, attrEndPos);

     if (filterTypeKnown && (tempFilterType == FILTER_TYPE_EXTENSIBLE_MATCH))
        {
          if (l > r)
          {
            throw new LDAPException(ResultCode.FILTER_ERROR,
                                    ERR_FILTER_NO_EQUALS.get(startPos));
          }

          final char c = filterString.charAt(l++);
          if (c == '=')
          {
            matchingRuleID = null;
            dnAttributes   = false;
          }
          else
          {
            boolean equalFound = false;
            final int substrStartPos = l - 1;
            while (l <= r)
            {
              if (filterString.charAt(l++) == '=')
              {
                equalFound = true;
                break;
              }
            }

            if (! equalFound)
            {
              throw new LDAPException(ResultCode.FILTER_ERROR,
                                      ERR_FILTER_NO_EQUALS.get(startPos));
            }

            final String substr = filterString.substring(substrStartPos, l-1);
            final String lowerSubstr = toLowerCase(substr);
            if (! substr.endsWith(":"))
            {
              throw new LDAPException(ResultCode.FILTER_ERROR,
                                      ERR_FILTER_CANNOT_PARSE_MRID.get(
                                           startPos));
            }

            if (lowerSubstr.equals("dn:"))
            {
              matchingRuleID = null;
              dnAttributes   = true;
            }
            else if (lowerSubstr.startsWith("dn:"))
            {
              matchingRuleID = substr.substring(3, substr.length() - 1);
              if (matchingRuleID.length() == 0)
              {
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_EMPTY_MRID.get(startPos));
              }

              dnAttributes   = true;
            }
            else
            {
              matchingRuleID = substr.substring(0, substr.length() - 1);
              dnAttributes   = false;

              if (matchingRuleID.length() == 0)
              {
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_EMPTY_MRID.get(startPos));
              }
            }
          }
        }
        else
        {
          matchingRuleID = null;
          dnAttributes   = false;
        }


        if (l > r)
        {
          assertionValue = new ASN1OctetString();
          if (! filterTypeKnown)
          {
            tempFilterType = FILTER_TYPE_EQUALITY;
          }

          subInitial = null;
          subAny     = NO_SUB_ANY;
          subFinal   = null;
        }
        else if (l == r)
        {
          if (filterTypeKnown)
          {
            switch (filterString.charAt(l))
            {
              case '*':
              case '(':
              case ')':
              case '\\':
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_UNEXPECTED_CHAR_IN_AV.get(
                                             filterString.charAt(l), startPos));
            }

            assertionValue =
                 new ASN1OctetString(filterString.substring(l, l+1));
          }
          else
          {
            final char c = filterString.charAt(l);
            switch (c)
            {
              case '*':
                tempFilterType = FILTER_TYPE_PRESENCE;
                assertionValue = null;
                break;

              case '\\':
              case '(':
              case ')':
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_UNEXPECTED_CHAR_IN_AV.get(
                                             filterString.charAt(l), startPos));

              default:
                tempFilterType = FILTER_TYPE_EQUALITY;
                assertionValue =
                     new ASN1OctetString(filterString.substring(l, l+1));
                break;
            }
          }

          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
        }
        else
        {
          if (! filterTypeKnown)
          {
            tempFilterType = FILTER_TYPE_EQUALITY;
          }

          final int valueStartPos = l;
          ASN1OctetString tempSubInitial = null;
          ASN1OctetString tempSubFinal   = null;
          final ArrayList<ASN1OctetString> subAnyList =
               new ArrayList<ASN1OctetString>(1);
          StringBuilder buffer = new StringBuilder(r - l + 1);
          while (l <= r)
          {
            final char c = filterString.charAt(l++);
            switch (c)
            {
              case '*':
                if (filterTypeKnown)
                {
                  throw new LDAPException(ResultCode.FILTER_ERROR,
                                          ERR_FILTER_UNEXPECTED_ASTERISK.get(
                                               startPos));
                }
                else
                {
                  if ((l-1) == valueStartPos)
                  {
                  }
                  else
                  {
                    if (tempFilterType == FILTER_TYPE_SUBSTRING)
                    {
                      if (buffer.length() == 0)
                      {
                        throw new LDAPException(ResultCode.FILTER_ERROR,
                             ERR_FILTER_UNEXPECTED_DOUBLE_ASTERISK.get(
                                  startPos));
                      }
                      else
                      {
                        subAnyList.add(new ASN1OctetString(buffer.toString()));
                        buffer = new StringBuilder(r - l + 1);
                      }
                    }
                    else
                    {
                      tempSubInitial = new ASN1OctetString(buffer.toString());
                      buffer = new StringBuilder(r - l + 1);
                    }
                  }

                  tempFilterType = FILTER_TYPE_SUBSTRING;
                }
                break;

              case '\\':
                l = readEscapedHexString(filterString, l, r, buffer);
                break;

              case '(':
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_UNEXPECTED_OPEN_PAREN.get(
                                             l));

              case ')':
                throw new LDAPException(ResultCode.FILTER_ERROR,
                                        ERR_FILTER_UNEXPECTED_CLOSE_PAREN.get(
                                             l));

              default:
                buffer.append(c);
                break;
            }
          }

          if ((tempFilterType == FILTER_TYPE_SUBSTRING) &&
              (buffer.length() > 0))
          {
            tempSubFinal = new ASN1OctetString(buffer.toString());
          }

          subInitial = tempSubInitial;
          subAny = subAnyList.toArray(new ASN1OctetString[subAnyList.size()]);
          subFinal = tempSubFinal;

          if (tempFilterType == FILTER_TYPE_SUBSTRING)
          {
            assertionValue = null;
          }
          else
          {
            assertionValue = new ASN1OctetString(buffer.toString());
          }
        }

        filterType = tempFilterType;
        break;
    }


    if (startPos == 0)
    {
      return new Filter(filterString, filterType, filterComps, notComp,
                        attrName, assertionValue, subInitial, subAny, subFinal,
                        matchingRuleID, dnAttributes);
    }
    else
    {
      return new Filter(filterString.substring(startPos, endPos+1), filterType,
                        filterComps, notComp, attrName, assertionValue,
                        subInitial, subAny, subFinal, matchingRuleID,
                        dnAttributes);
    }
  }


  private static Filter[] parseFilterComps(final String filterString,
                                           final int startPos, final int endPos,
                                           final int depth)
          throws LDAPException
  {
    if (startPos > endPos)
    {
      return NO_FILTERS;
    }

    if (filterString.charAt(startPos) != '(')
    {
      throw new LDAPException(ResultCode.FILTER_ERROR,
                              ERR_FILTER_EXPECTED_OPEN_PAREN.get(startPos));
    }
    if (filterString.charAt(endPos) != ')')
    {
      throw new LDAPException(ResultCode.FILTER_ERROR,
                              ERR_FILTER_EXPECTED_CLOSE_PAREN.get(startPos));
    }

    final ArrayList<Filter> filterList = new ArrayList<Filter>(5);
    int filterStartPos = startPos;
    int pos = startPos;
    int numOpen = 0;
    while (pos <= endPos)
    {
      final char c = filterString.charAt(pos++);
      if (c == '(')
      {
        numOpen++;
      }
      else if (c == ')')
      {
        numOpen--;
        if (numOpen == 0)
        {
          filterList.add(create(filterString, filterStartPos, pos-1, depth));
          filterStartPos = pos;
        }
      }
    }

    if (numOpen != 0)
    {
      throw new LDAPException(ResultCode.FILTER_ERROR,
                              ERR_FILTER_MISMATCHED_PARENS.get(startPos,
                                                               endPos));
    }

    return filterList.toArray(new Filter[filterList.size()]);
  }


  private static int readEscapedHexString(final String filterString,
                                          final int startPos, final int endPos,
                                          final StringBuilder buffer)
          throws LDAPException
  {
    int pos = startPos;

    final ByteBuffer byteBuffer = ByteBuffer.allocate(endPos - startPos);
    while (pos <= endPos)
    {
      byte b;
      switch (filterString.charAt(pos++))
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
          throw new LDAPException(ResultCode.FILTER_ERROR,
                                  ERR_FILTER_INVALID_HEX_CHAR.get(
                                       filterString.charAt(pos-1), (pos-1)));
      }

      if (pos > endPos)
      {
        throw new LDAPException(ResultCode.FILTER_ERROR,
                                ERR_FILTER_INVALID_ESCAPED_END_CHAR.get(
                                     filterString.charAt(pos-1)));
      }

      switch (filterString.charAt(pos++))
      {
        case '0':
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
          throw new LDAPException(ResultCode.FILTER_ERROR,
                                  ERR_FILTER_INVALID_HEX_CHAR.get(
                                       filterString.charAt(pos-1), (pos-1)));
      }

      byteBuffer.put(b);
      if ((pos <= endPos) && (filterString.charAt(pos) == '\\'))
      {
        pos++;
        continue;
      }
      else
      {
        break;
      }
    }

    byteBuffer.flip();
    final byte[] byteArray = new byte[byteBuffer.limit()];
    byteBuffer.get(byteArray);

    buffer.append(toUTF8String(byteArray));
    return pos;
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    switch (filterType)
    {
      case FILTER_TYPE_AND:
      case FILTER_TYPE_OR:
        final ASN1BufferSet compSet = buffer.beginSet(filterType);
        for (final Filter f : filterComps)
        {
          f.writeTo(buffer);
        }
        compSet.end();
        break;

      case FILTER_TYPE_NOT:
        buffer.addElement(
             new ASN1Element(filterType, notComp.encode().encode()));
        break;

      case FILTER_TYPE_EQUALITY:
      case FILTER_TYPE_GREATER_OR_EQUAL:
      case FILTER_TYPE_LESS_OR_EQUAL:
      case FILTER_TYPE_APPROXIMATE_MATCH:
        final ASN1BufferSequence avaSequence = buffer.beginSequence(filterType);
        buffer.addOctetString(attrName);
        buffer.addElement(assertionValue);
        avaSequence.end();
        break;

      case FILTER_TYPE_SUBSTRING:
        final ASN1BufferSequence subFilterSequence =
             buffer.beginSequence(filterType);
        buffer.addOctetString(attrName);

        final ASN1BufferSequence valueSequence = buffer.beginSequence();
        if (subInitial != null)
        {
          buffer.addOctetString(SUBSTRING_TYPE_SUBINITIAL,
                                subInitial.getValue());
        }

        for (final ASN1OctetString s : subAny)
        {
          buffer.addOctetString(SUBSTRING_TYPE_SUBANY, s.getValue());
        }

        if (subFinal != null)
        {
          buffer.addOctetString(SUBSTRING_TYPE_SUBFINAL, subFinal.getValue());
        }
        valueSequence.end();
        subFilterSequence.end();
        break;

      case FILTER_TYPE_PRESENCE:
        buffer.addOctetString(filterType, attrName);
        break;

      case FILTER_TYPE_EXTENSIBLE_MATCH:
        final ASN1BufferSequence mrSequence = buffer.beginSequence(filterType);
        if (matchingRuleID != null)
        {
          buffer.addOctetString(EXTENSIBLE_TYPE_MATCHING_RULE_ID,
                                matchingRuleID);
        }

        if (attrName != null)
        {
          buffer.addOctetString(EXTENSIBLE_TYPE_ATTRIBUTE_NAME, attrName);
        }

        buffer.addOctetString(EXTENSIBLE_TYPE_MATCH_VALUE,
                              assertionValue.getValue());

        if (dnAttributes)
        {
          buffer.addBoolean(EXTENSIBLE_TYPE_DN_ATTRIBUTES, true);
        }
        mrSequence.end();
        break;
    }
  }


  public ASN1Element encode()
  {
    switch (filterType)
    {
      case FILTER_TYPE_AND:
      case FILTER_TYPE_OR:
        final ASN1Element[] filterElements =
             new ASN1Element[filterComps.length];
        for (int i=0; i < filterComps.length; i++)
        {
          filterElements[i] = filterComps[i].encode();
        }
        return new ASN1Set(filterType, filterElements);


      case FILTER_TYPE_NOT:
        return new ASN1Element(filterType, notComp.encode().encode());


      case FILTER_TYPE_EQUALITY:
      case FILTER_TYPE_GREATER_OR_EQUAL:
      case FILTER_TYPE_LESS_OR_EQUAL:
      case FILTER_TYPE_APPROXIMATE_MATCH:
        final ASN1OctetString[] attrValueAssertionElements =
        {
          new ASN1OctetString(attrName),
          assertionValue
        };
        return new ASN1Sequence(filterType, attrValueAssertionElements);


      case FILTER_TYPE_SUBSTRING:
        final ArrayList<ASN1OctetString> subList =
             new ArrayList<ASN1OctetString>(2 + subAny.length);
        if (subInitial != null)
        {
          subList.add(new ASN1OctetString(SUBSTRING_TYPE_SUBINITIAL,
                                          subInitial.getValue()));
        }

        for (final ASN1Element subAnyElement : subAny)
        {
          subList.add(new ASN1OctetString(SUBSTRING_TYPE_SUBANY,
                                          subAnyElement.getValue()));
        }


        if (subFinal != null)
        {
          subList.add(new ASN1OctetString(SUBSTRING_TYPE_SUBFINAL,
                                          subFinal.getValue()));
        }

        final ASN1Element[] subFilterElements =
        {
          new ASN1OctetString(attrName),
          new ASN1Sequence(subList)
        };
        return new ASN1Sequence(filterType, subFilterElements);


      case FILTER_TYPE_PRESENCE:
        return new ASN1OctetString(filterType, attrName);


      case FILTER_TYPE_EXTENSIBLE_MATCH:
        final ArrayList<ASN1Element> emElementList =
             new ArrayList<ASN1Element>(4);
        if (matchingRuleID != null)
        {
          emElementList.add(new ASN1OctetString(
               EXTENSIBLE_TYPE_MATCHING_RULE_ID, matchingRuleID));
        }

        if (attrName != null)
        {
          emElementList.add(new ASN1OctetString(
               EXTENSIBLE_TYPE_ATTRIBUTE_NAME, attrName));
        }

        emElementList.add(new ASN1OctetString(EXTENSIBLE_TYPE_MATCH_VALUE,
                                              assertionValue.getValue()));

        if (dnAttributes)
        {
          emElementList.add(new ASN1Boolean(EXTENSIBLE_TYPE_DN_ATTRIBUTES,
                                            true));
        }

        return new ASN1Sequence(filterType, emElementList);


      default:
        throw new AssertionError(ERR_FILTER_INVALID_TYPE.get(
                                      toHex(filterType)));
    }
  }


  public static Filter readFrom(final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final Filter[]          filterComps;
      final Filter            notComp;
      final String            attrName;
      final ASN1OctetString   assertionValue;
      final ASN1OctetString   subInitial;
      final ASN1OctetString[] subAny;
      final ASN1OctetString   subFinal;
      final String            matchingRuleID;
      final boolean           dnAttributes;

      final byte filterType = (byte) reader.peek();

      switch (filterType)
      {
        case FILTER_TYPE_AND:
        case FILTER_TYPE_OR:
          final ArrayList<Filter> comps = new ArrayList<Filter>(5);
          final ASN1StreamReaderSet elementSet = reader.beginSet();
          while (elementSet.hasMoreElements())
          {
            comps.add(readFrom(reader));
          }

          filterComps = new Filter[comps.size()];
          comps.toArray(filterComps);

          notComp        = null;
          attrName       = null;
          assertionValue = null;
          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
          matchingRuleID = null;
          dnAttributes   = false;
          break;


        case FILTER_TYPE_NOT:
          final ASN1Element notFilterElement;
          try
          {
            final ASN1Element e = reader.readElement();
            notFilterElement = ASN1Element.decode(e.getValue());
          }
          catch (final ASN1Exception ae)
          {
            debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_FILTER_CANNOT_DECODE_NOT_COMP.get(getExceptionMessage(ae)),
                 ae);
          }
          notComp = decode(notFilterElement);

          filterComps    = NO_FILTERS;
          attrName       = null;
          assertionValue = null;
          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
          matchingRuleID = null;
          dnAttributes   = false;
          break;


        case FILTER_TYPE_EQUALITY:
        case FILTER_TYPE_GREATER_OR_EQUAL:
        case FILTER_TYPE_LESS_OR_EQUAL:
        case FILTER_TYPE_APPROXIMATE_MATCH:
          reader.beginSequence();
          attrName = reader.readString();
          assertionValue = new ASN1OctetString(reader.readBytes());

          filterComps    = NO_FILTERS;
          notComp        = null;
          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
          matchingRuleID = null;
          dnAttributes   = false;
          break;


        case FILTER_TYPE_SUBSTRING:
          reader.beginSequence();
          attrName = reader.readString();

          ASN1OctetString tempSubInitial = null;
          ASN1OctetString tempSubFinal   = null;
          final ArrayList<ASN1OctetString> subAnyList =
               new ArrayList<ASN1OctetString>(1);
          final ASN1StreamReaderSequence subSequence = reader.beginSequence();
          while (subSequence.hasMoreElements())
          {
            final byte type = (byte) reader.peek();
            final ASN1OctetString s =
                 new ASN1OctetString(type, reader.readBytes());
            switch (type)
            {
              case SUBSTRING_TYPE_SUBINITIAL:
                tempSubInitial = s;
                break;
              case SUBSTRING_TYPE_SUBANY:
                subAnyList.add(s);
                break;
              case SUBSTRING_TYPE_SUBFINAL:
                tempSubFinal = s;
                break;
              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_FILTER_INVALID_SUBSTR_TYPE.get(toHex(type)));
            }
          }

          subInitial = tempSubInitial;
          subFinal   = tempSubFinal;

          subAny = new ASN1OctetString[subAnyList.size()];
          subAnyList.toArray(subAny);

          filterComps    = NO_FILTERS;
          notComp        = null;
          assertionValue = null;
          matchingRuleID = null;
          dnAttributes   = false;
          break;


        case FILTER_TYPE_PRESENCE:
          attrName = reader.readString();

          filterComps    = NO_FILTERS;
          notComp        = null;
          assertionValue = null;
          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
          matchingRuleID = null;
          dnAttributes   = false;
          break;


        case FILTER_TYPE_EXTENSIBLE_MATCH:
          String          tempAttrName       = null;
          ASN1OctetString tempAssertionValue = null;
          String          tempMatchingRuleID = null;
          boolean         tempDNAttributes   = false;

          final ASN1StreamReaderSequence emSequence = reader.beginSequence();
          while (emSequence.hasMoreElements())
          {
            final byte type = (byte) reader.peek();
            switch (type)
            {
              case EXTENSIBLE_TYPE_ATTRIBUTE_NAME:
                tempAttrName = reader.readString();
                break;
              case EXTENSIBLE_TYPE_MATCHING_RULE_ID:
                tempMatchingRuleID = reader.readString();
                break;
              case EXTENSIBLE_TYPE_MATCH_VALUE:
                tempAssertionValue =
                     new ASN1OctetString(type, reader.readBytes());
                break;
              case EXTENSIBLE_TYPE_DN_ATTRIBUTES:
                tempDNAttributes = reader.readBoolean();
                break;
              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_FILTER_EXTMATCH_INVALID_TYPE.get(toHex(type)));
            }
          }

          if ((tempAttrName == null) && (tempMatchingRuleID == null))
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_FILTER_EXTMATCH_NO_ATTR_OR_MRID.get());
          }

          if (tempAssertionValue == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_FILTER_EXTMATCH_NO_VALUE.get());
          }

          attrName       = tempAttrName;
          assertionValue = tempAssertionValue;
          matchingRuleID = tempMatchingRuleID;
          dnAttributes   = tempDNAttributes;

          filterComps    = NO_FILTERS;
          notComp        = null;
          subInitial     = null;
          subAny         = NO_SUB_ANY;
          subFinal       = null;
          break;


        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_ELEMENT_INVALID_TYPE.get(toHex(filterType)));
      }

      return new Filter(null, filterType, filterComps, notComp, attrName,
                        assertionValue, subInitial, subAny, subFinal,
                        matchingRuleID, dnAttributes);
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
           ERR_FILTER_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }

  public static Filter decode(final ASN1Element filterElement)
         throws LDAPException
  {
    final byte              filterType = filterElement.getType();
    final Filter[]          filterComps;
    final Filter            notComp;
    final String            attrName;
    final ASN1OctetString   assertionValue;
    final ASN1OctetString   subInitial;
    final ASN1OctetString[] subAny;
    final ASN1OctetString   subFinal;
    final String            matchingRuleID;
    final boolean           dnAttributes;

    switch (filterType)
    {
      case FILTER_TYPE_AND:
      case FILTER_TYPE_OR:
        notComp        = null;
        attrName       = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;

        final ASN1Set compSet;
        try
        {
          compSet = ASN1Set.decodeAsSet(filterElement);
        }
        catch (final ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_COMPS.get(getExceptionMessage(ae)), ae);
        }

        final ASN1Element[] compElements = compSet.elements();
        filterComps = new Filter[compElements.length];
        for (int i=0; i < compElements.length; i++)
        {
          filterComps[i] = decode(compElements[i]);
        }
        break;


      case FILTER_TYPE_NOT:
        filterComps    = NO_FILTERS;
        attrName       = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;

        final ASN1Element notFilterElement;
        try
        {
          notFilterElement = ASN1Element.decode(filterElement.getValue());
        }
        catch (final ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_NOT_COMP.get(getExceptionMessage(ae)),
               ae);
        }
        notComp = decode(notFilterElement);
        break;



      case FILTER_TYPE_EQUALITY:
      case FILTER_TYPE_GREATER_OR_EQUAL:
      case FILTER_TYPE_LESS_OR_EQUAL:
      case FILTER_TYPE_APPROXIMATE_MATCH:
        filterComps    = NO_FILTERS;
        notComp        = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;

        final ASN1Sequence avaSequence;
        try
        {
          avaSequence = ASN1Sequence.decodeAsSequence(filterElement);
        }
        catch (final ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_AVA.get(getExceptionMessage(ae)), ae);
        }

        final ASN1Element[] avaElements = avaSequence.elements();
        if (avaElements.length != 2)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_FILTER_INVALID_AVA_ELEMENT_COUNT.get(
                                       avaElements.length));
        }

        attrName =
             ASN1OctetString.decodeAsOctetString(avaElements[0]).stringValue();
        assertionValue = ASN1OctetString.decodeAsOctetString(avaElements[1]);
        break;


      case FILTER_TYPE_SUBSTRING:
        filterComps    = NO_FILTERS;
        notComp        = null;
        assertionValue = null;
        matchingRuleID = null;
        dnAttributes   = false;

        final ASN1Sequence subFilterSequence;
        try
        {
          subFilterSequence = ASN1Sequence.decodeAsSequence(filterElement);
        }
        catch (final ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_SUBSTRING.get(getExceptionMessage(ae)),
               ae);
        }

        final ASN1Element[] subFilterElements = subFilterSequence.elements();
        if (subFilterElements.length != 2)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_FILTER_INVALID_SUBSTR_ASSERTION_COUNT.get(
                                       subFilterElements.length));
        }

        attrName = ASN1OctetString.decodeAsOctetString(
                        subFilterElements[0]).stringValue();

        final ASN1Sequence subSequence;
        try
        {
          subSequence = ASN1Sequence.decodeAsSequence(subFilterElements[1]);
        }
        catch (ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_SUBSTRING.get(getExceptionMessage(ae)),
               ae);
        }

        ASN1OctetString tempSubInitial = null;
        ASN1OctetString tempSubFinal   = null;
        final ArrayList<ASN1OctetString> subAnyList =
             new ArrayList<ASN1OctetString>(1);

        final ASN1Element[] subElements = subSequence.elements();
        for (final ASN1Element subElement : subElements)
        {
          switch (subElement.getType())
          {
            case SUBSTRING_TYPE_SUBINITIAL:
              if (tempSubInitial == null)
              {
                tempSubInitial =
                     ASN1OctetString.decodeAsOctetString(subElement);
              }
              else
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                                        ERR_FILTER_MULTIPLE_SUBINITIAL.get());
              }
              break;

            case SUBSTRING_TYPE_SUBANY:
              subAnyList.add(ASN1OctetString.decodeAsOctetString(subElement));
              break;

            case SUBSTRING_TYPE_SUBFINAL:
              if (tempSubFinal == null)
              {
                tempSubFinal = ASN1OctetString.decodeAsOctetString(subElement);
              }
              else
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                                        ERR_FILTER_MULTIPLE_SUBFINAL.get());
              }
              break;

            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_FILTER_INVALID_SUBSTR_TYPE.get(
                                           toHex(subElement.getType())));
          }
        }

        subInitial = tempSubInitial;
        subAny     = subAnyList.toArray(new ASN1OctetString[subAnyList.size()]);
        subFinal   = tempSubFinal;
        break;


      case FILTER_TYPE_PRESENCE:
        filterComps    = NO_FILTERS;
        notComp        = null;
        assertionValue = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;
        matchingRuleID = null;
        dnAttributes   = false;
        attrName       =
             ASN1OctetString.decodeAsOctetString(filterElement).stringValue();
        break;


      case FILTER_TYPE_EXTENSIBLE_MATCH:
        filterComps    = NO_FILTERS;
        notComp        = null;
        subInitial     = null;
        subAny         = NO_SUB_ANY;
        subFinal       = null;

        final ASN1Sequence emSequence;
        try
        {
          emSequence = ASN1Sequence.decodeAsSequence(filterElement);
        }
        catch (ASN1Exception ae)
        {
          debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_FILTER_CANNOT_DECODE_EXTMATCH.get(getExceptionMessage(ae)),
               ae);
        }

        String          tempAttrName       = null;
        ASN1OctetString tempAssertionValue = null;
        String          tempMatchingRuleID = null;
        boolean         tempDNAttributes   = false;
        for (final ASN1Element e : emSequence.elements())
        {
          switch (e.getType())
          {
            case EXTENSIBLE_TYPE_ATTRIBUTE_NAME:
              if (tempAttrName == null)
              {
                tempAttrName =
                     ASN1OctetString.decodeAsOctetString(e).stringValue();
              }
              else
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                               ERR_FILTER_EXTMATCH_MULTIPLE_ATTRS.get());
              }
              break;

            case EXTENSIBLE_TYPE_MATCHING_RULE_ID:
              if (tempMatchingRuleID == null)
              {
                tempMatchingRuleID  =
                     ASN1OctetString.decodeAsOctetString(e).stringValue();
              }
              else
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                               ERR_FILTER_EXTMATCH_MULTIPLE_MRIDS.get());
              }
              break;

            case EXTENSIBLE_TYPE_MATCH_VALUE:
              if (tempAssertionValue == null)
              {
                tempAssertionValue = ASN1OctetString.decodeAsOctetString(e);
              }
              else
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                               ERR_FILTER_EXTMATCH_MULTIPLE_VALUES.get());
              }
              break;

            case EXTENSIBLE_TYPE_DN_ATTRIBUTES:
              try
              {
                if (tempDNAttributes)
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_FILTER_EXTMATCH_MULTIPLE_DNATTRS.get());
                }
                else
                {
                  tempDNAttributes =
                       ASN1Boolean.decodeAsBoolean(e).booleanValue();
                }
              }
              catch (ASN1Exception ae)
              {
                debugException(ae);
                throw new LDAPException(ResultCode.DECODING_ERROR,
                               ERR_FILTER_EXTMATCH_DNATTRS_NOT_BOOLEAN.get(
                                    getExceptionMessage(ae)),
                               ae);
              }
              break;

            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_FILTER_EXTMATCH_INVALID_TYPE.get(
                                           toHex(e.getType())));
          }
        }

        if ((tempAttrName == null) && (tempMatchingRuleID == null))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_FILTER_EXTMATCH_NO_ATTR_OR_MRID.get());
        }

        if (tempAssertionValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_FILTER_EXTMATCH_NO_VALUE.get());
        }

        attrName       = tempAttrName;
        assertionValue = tempAssertionValue;
        matchingRuleID = tempMatchingRuleID;
        dnAttributes   = tempDNAttributes;
        break;


      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_FILTER_ELEMENT_INVALID_TYPE.get(
                                     toHex(filterElement.getType())));
    }


    return new Filter(null, filterType, filterComps, notComp, attrName,
                      assertionValue, subInitial, subAny, subFinal,
                      matchingRuleID, dnAttributes);
  }



  public byte getFilterType()
  {
    return filterType;
  }


  public Filter[] getComponents()
  {
    return filterComps;
  }

  public Filter getNOTComponent()
  {
    return notComp;
  }



  public String getAttributeName()
  {
    return attrName;
  }



  public String getAssertionValue()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.stringValue();
    }
  }

  public byte[] getAssertionValueBytes()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.getValue();
    }
  }


  public ASN1OctetString getRawAssertionValue()
  {
    return assertionValue;
  }



  public String getSubInitialString()
  {
    if (subInitial == null)
    {
      return null;
    }
    else
    {
      return subInitial.stringValue();
    }
  }

  public byte[] getSubInitialBytes()
  {
    if (subInitial == null)
    {
      return null;
    }
    else
    {
      return subInitial.getValue();
    }
  }



  public ASN1OctetString getRawSubInitialValue()
  {
    return subInitial;
  }


  public String[] getSubAnyStrings()
  {
    final String[] subAnyStrings = new String[subAny.length];
    for (int i=0; i < subAny.length; i++)
    {
      subAnyStrings[i] = subAny[i].stringValue();
    }

    return subAnyStrings;
  }



  public byte[][] getSubAnyBytes()
  {
    final byte[][] subAnyBytes = new byte[subAny.length][];
    for (int i=0; i < subAny.length; i++)
    {
      subAnyBytes[i] = subAny[i].getValue();
    }

    return subAnyBytes;
  }


  public ASN1OctetString[] getRawSubAnyValues()
  {
    return subAny;
  }



  public String getSubFinalString()
  {
    if (subFinal == null)
    {
      return null;
    }
    else
    {
      return subFinal.stringValue();
    }
  }


  public byte[] getSubFinalBytes()
  {
    if (subFinal == null)
    {
      return null;
    }
    else
    {
      return subFinal.getValue();
    }
  }


  public ASN1OctetString getRawSubFinalValue()
  {
    return subFinal;
  }

  public String getMatchingRuleID()
  {
    return matchingRuleID;
  }

  public boolean getDNAttributes()
  {
    return dnAttributes;
  }

  public boolean matchesEntry(final Entry entry)
         throws LDAPException
  {
    return matchesEntry(entry, entry.getSchema());
  }


  public boolean matchesEntry(final Entry entry, final Schema schema)
         throws LDAPException
  {
    ensureNotNull(entry);

    switch (filterType)
    {
      case FILTER_TYPE_AND:
        for (final Filter f : filterComps)
        {
          if (! f.matchesEntry(entry, schema))
          {
            return false;
          }
        }
        return true;

      case FILTER_TYPE_OR:
        for (final Filter f : filterComps)
        {
          if (f.matchesEntry(entry, schema))
          {
            return true;
          }
        }
        return false;

      case FILTER_TYPE_NOT:
        return (! notComp.matchesEntry(entry, schema));

      case FILTER_TYPE_EQUALITY:
        Attribute a = entry.getAttribute(attrName, schema);
        if (a == null)
        {
          return false;
        }

        MatchingRule matchingRule =
             MatchingRule.selectEqualityMatchingRule(attrName, schema);
        for (final ASN1OctetString v : a.getRawValues())
        {
          if (matchingRule.valuesMatch(v, assertionValue))
          {
            return true;
          }
        }
        return false;

      case FILTER_TYPE_SUBSTRING:
        a = entry.getAttribute(attrName, schema);
        if (a == null)
        {
          return false;
        }

        matchingRule =
             MatchingRule.selectSubstringMatchingRule(attrName, schema);
        for (final ASN1OctetString v : a.getRawValues())
        {
          if (matchingRule.matchesSubstring(v, subInitial, subAny, subFinal))
          {
            return true;
          }
        }
        return false;

      case FILTER_TYPE_GREATER_OR_EQUAL:
        a = entry.getAttribute(attrName, schema);
        if (a == null)
        {
          return false;
        }

        matchingRule =
             MatchingRule.selectOrderingMatchingRule(attrName, schema);
        for (final ASN1OctetString v : a.getRawValues())
        {
          if (matchingRule.compareValues(v, assertionValue) >= 0)
          {
            return true;
          }
        }
        return false;

      case FILTER_TYPE_LESS_OR_EQUAL:
        a = entry.getAttribute(attrName, schema);
        if (a == null)
        {
          return false;
        }

        matchingRule =
             MatchingRule.selectOrderingMatchingRule(attrName, schema);
        for (final ASN1OctetString v : a.getRawValues())
        {
          if (matchingRule.compareValues(v, assertionValue) <= 0)
          {
            return true;
          }
        }
        return false;

      case FILTER_TYPE_PRESENCE:
        return (entry.hasAttribute(attrName));

      case FILTER_TYPE_APPROXIMATE_MATCH:
        throw new LDAPException(ResultCode.NOT_SUPPORTED,
             ERR_FILTER_APPROXIMATE_MATCHING_NOT_SUPPORTED.get());

      case FILTER_TYPE_EXTENSIBLE_MATCH:
        throw new LDAPException(ResultCode.NOT_SUPPORTED,
             ERR_FILTER_EXTENSIBLE_MATCHING_NOT_SUPPORTED.get());

      default:
        throw new LDAPException(ResultCode.PARAM_ERROR,
                                ERR_FILTER_INVALID_TYPE.get());
    }
  }


  @Override()
  public int hashCode()
  {
    final CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    int hashCode = filterType;

    switch (filterType)
    {
      case FILTER_TYPE_AND:
      case FILTER_TYPE_OR:
        for (final Filter f : filterComps)
        {
          hashCode += f.hashCode();
        }
        break;

      case FILTER_TYPE_NOT:
        hashCode += notComp.hashCode();
        break;

      case FILTER_TYPE_EQUALITY:
      case FILTER_TYPE_GREATER_OR_EQUAL:
      case FILTER_TYPE_LESS_OR_EQUAL:
      case FILTER_TYPE_APPROXIMATE_MATCH:
        hashCode += toLowerCase(attrName).hashCode();
        hashCode += matchingRule.normalize(assertionValue).hashCode();
        break;

      case FILTER_TYPE_SUBSTRING:
        hashCode += toLowerCase(attrName).hashCode();
        if (subInitial != null)
        {
          hashCode += matchingRule.normalizeSubstring(subInitial,
                           MatchingRule.SUBSTRING_TYPE_SUBINITIAL).hashCode();
        }
        for (final ASN1OctetString s : subAny)
        {
          hashCode += matchingRule.normalizeSubstring(s,
                           MatchingRule.SUBSTRING_TYPE_SUBANY).hashCode();
        }
        if (subFinal != null)
        {
          hashCode += matchingRule.normalizeSubstring(subFinal,
                           MatchingRule.SUBSTRING_TYPE_SUBFINAL).hashCode();
        }
        break;

      case FILTER_TYPE_PRESENCE:
        hashCode += toLowerCase(attrName).hashCode();
        break;

      case FILTER_TYPE_EXTENSIBLE_MATCH:
        if (attrName != null)
        {
          hashCode += toLowerCase(attrName).hashCode();
        }

        if (matchingRuleID != null)
        {
          hashCode += toLowerCase(matchingRuleID).hashCode();
        }

        if (dnAttributes)
        {
          hashCode++;
        }

        hashCode += matchingRule.normalize(assertionValue).hashCode();
        break;
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

    if (! (o instanceof Filter))
    {
      return false;
    }

    final Filter f = (Filter) o;
    if (filterType != f.filterType)
    {
      return false;
    }

    final CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();

    switch (filterType)
    {
      case FILTER_TYPE_AND:
      case FILTER_TYPE_OR:
        if (filterComps.length != f.filterComps.length)
        {
          return false;
        }

        final HashSet<Filter> compSet = new HashSet<Filter>();
        compSet.addAll(Arrays.asList(filterComps));

        for (final Filter filterComp : f.filterComps)
        {
          if (! compSet.remove(filterComp))
          {
            return false;
          }
        }

        return true;


    case FILTER_TYPE_NOT:
      return notComp.equals(f.notComp);


      case FILTER_TYPE_EQUALITY:
      case FILTER_TYPE_GREATER_OR_EQUAL:
      case FILTER_TYPE_LESS_OR_EQUAL:
      case FILTER_TYPE_APPROXIMATE_MATCH:
        return (attrName.equalsIgnoreCase(f.attrName) &&
                matchingRule.valuesMatch(assertionValue, f.assertionValue));


      case FILTER_TYPE_SUBSTRING:
        if (! attrName.equalsIgnoreCase(f.attrName))
        {
          return false;
        }

        if (subAny.length != f.subAny.length)
        {
          return false;
        }

        if (subInitial == null)
        {
          if (f.subInitial != null)
          {
            return false;
          }
        }
        else
        {
          if (f.subInitial == null)
          {
            return false;
          }

          final ASN1OctetString si1 = matchingRule.normalizeSubstring(
               subInitial, MatchingRule.SUBSTRING_TYPE_SUBINITIAL);
          final ASN1OctetString si2 = matchingRule.normalizeSubstring(
               f.subInitial, MatchingRule.SUBSTRING_TYPE_SUBINITIAL);
          if (! si1.equals(si2))
          {
            return false;
          }
        }

        for (int i=0; i < subAny.length; i++)
        {
          final ASN1OctetString sa1 = matchingRule.normalizeSubstring(subAny[i],
               MatchingRule.SUBSTRING_TYPE_SUBANY);
          final ASN1OctetString sa2 = matchingRule.normalizeSubstring(
               f.subAny[i], MatchingRule.SUBSTRING_TYPE_SUBANY);
          if (! sa1.equals(sa2))
          {
            return false;
          }
        }

        if (subFinal == null)
        {
          if (f.subFinal != null)
          {
            return false;
          }
        }
        else
        {
          if (f.subFinal == null)
          {
            return false;
          }

          final ASN1OctetString sf1 = matchingRule.normalizeSubstring(subFinal,
               MatchingRule.SUBSTRING_TYPE_SUBFINAL);
          final ASN1OctetString sf2 = matchingRule.normalizeSubstring(
               f.subFinal, MatchingRule.SUBSTRING_TYPE_SUBFINAL);
          if (! sf1.equals(sf2))
          {
            return false;
          }
        }

        return true;


      case FILTER_TYPE_PRESENCE:
        return (attrName.equalsIgnoreCase(f.attrName));


      case FILTER_TYPE_EXTENSIBLE_MATCH:
        if (attrName == null)
        {
          if (f.attrName != null)
          {
            return false;
          }
        }
        else
        {
          if (f.attrName == null)
          {
            return false;
          }
          else
          {
            if (! attrName.equalsIgnoreCase(f.attrName))
            {
              return false;
            }
          }
        }

        if (matchingRuleID == null)
        {
          if (f.matchingRuleID != null)
          {
            return false;
          }
        }
        else
        {
          if (f.matchingRuleID == null)
          {
            return false;
          }
          else
          {
            if (! matchingRuleID.equalsIgnoreCase(f.matchingRuleID))
            {
              return false;
            }
          }
        }

        if (dnAttributes != f.dnAttributes)
        {
          return false;
        }

        return matchingRule.valuesMatch(assertionValue, f.assertionValue);


      default:
        return false;
    }
  }



  @Override()
  public String toString()
  {
    if (filterString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer);
      filterString = buffer.toString();
    }

    return filterString;
  }


  public void toString(final StringBuilder buffer)
  {
    switch (filterType)
    {
      case FILTER_TYPE_AND:
        buffer.append("(&");
        for (final Filter f : filterComps)
        {
          f.toString(buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_OR:
        buffer.append("(|");
        for (final Filter f : filterComps)
        {
          f.toString(buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_NOT:
        buffer.append("(!");
        notComp.toString(buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_EQUALITY:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append('=');
        encodeValue(assertionValue, buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_SUBSTRING:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append('=');
        if (subInitial != null)
        {
          encodeValue(subInitial, buffer);
        }
        buffer.append('*');
        for (final ASN1OctetString s : subAny)
        {
          encodeValue(s, buffer);
          buffer.append('*');
        }
        if (subFinal != null)
        {
          encodeValue(subFinal, buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_GREATER_OR_EQUAL:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append(">=");
        encodeValue(assertionValue, buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_LESS_OR_EQUAL:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append("<=");
        encodeValue(assertionValue, buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_PRESENCE:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append("=*)");
        break;

      case FILTER_TYPE_APPROXIMATE_MATCH:
        buffer.append('(');
        buffer.append(attrName);
        buffer.append("~=");
        encodeValue(assertionValue, buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_EXTENSIBLE_MATCH:
        buffer.append('(');
        if (attrName != null)
        {
          buffer.append(attrName);
        }

        if (dnAttributes)
        {
          buffer.append(":dn");
        }

        if (matchingRuleID != null)
        {
          buffer.append(':');
          buffer.append(matchingRuleID);
        }

        buffer.append(":=");
        encodeValue(assertionValue, buffer);
        buffer.append(')');
        break;
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
    final CaseIgnoreStringMatchingRule mr =
         CaseIgnoreStringMatchingRule.getInstance();

    switch (filterType)
    {
      case FILTER_TYPE_AND:
        buffer.append("(&");
        for (final Filter f : filterComps)
        {
          f.toNormalizedString(buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_OR:
        buffer.append("(|");
        for (final Filter f : filterComps)
        {
          f.toNormalizedString(buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_NOT:
        buffer.append("(!");
        notComp.toNormalizedString(buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_EQUALITY:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append('=');
        encodeValue(mr.normalize(assertionValue), buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_SUBSTRING:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append('=');
        if (subInitial != null)
        {
          encodeValue(mr.normalizeSubstring(subInitial,
                           MatchingRule.SUBSTRING_TYPE_SUBINITIAL), buffer);
        }
        buffer.append('*');
        for (final ASN1OctetString s : subAny)
        {
          encodeValue(mr.normalizeSubstring(s,
                           MatchingRule.SUBSTRING_TYPE_SUBANY), buffer);
          buffer.append('*');
        }
        if (subFinal != null)
        {
          encodeValue(mr.normalizeSubstring(subFinal,
                           MatchingRule.SUBSTRING_TYPE_SUBFINAL), buffer);
        }
        buffer.append(')');
        break;

      case FILTER_TYPE_GREATER_OR_EQUAL:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append(">=");
        encodeValue(mr.normalize(assertionValue), buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_LESS_OR_EQUAL:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append("<=");
        encodeValue(mr.normalize(assertionValue), buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_PRESENCE:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append("=*)");
        break;

      case FILTER_TYPE_APPROXIMATE_MATCH:
        buffer.append('(');
        buffer.append(toLowerCase(attrName));
        buffer.append("~=");
        encodeValue(mr.normalize(assertionValue), buffer);
        buffer.append(')');
        break;

      case FILTER_TYPE_EXTENSIBLE_MATCH:
        buffer.append('(');
        if (attrName != null)
        {
          buffer.append(toLowerCase(attrName));
        }

        if (dnAttributes)
        {
          buffer.append(":dn");
        }

        if (matchingRuleID != null)
        {
          buffer.append(':');
          buffer.append(toLowerCase(matchingRuleID));
        }

        buffer.append(":=");
        encodeValue(mr.normalize(assertionValue), buffer);
        buffer.append(')');
        break;
    }
  }


  public static String encodeValue(final String value)
  {
    ensureNotNull(value);

    final StringBuilder buffer = new StringBuilder();
    encodeValue(new ASN1OctetString(value), buffer);
    return buffer.toString();
  }


  public static String encodeValue(final byte[]value)
  {
    ensureNotNull(value);

    final StringBuilder buffer = new StringBuilder();
    encodeValue(new ASN1OctetString(value), buffer);
    return buffer.toString();
  }


  private static void encodeValue(final ASN1OctetString value,
                                  final StringBuilder buffer)
  {
    final String valueString = value.stringValue();
    final int length = valueString.length();
    for (int i=0; i < length; i++)
    {
      final char c = valueString.charAt(i);
      switch (c)
      {
        case '\u0000':
        case '(':
        case ')':
        case '*':
        case '\\':
          hexEncode(c, buffer);
          break;

        default:
          if (c <= 0x7F)
          {
            buffer.append(c);
          }
          else
          {
            hexEncode(c, buffer);
          }
          break;
      }
    }
  }
}
