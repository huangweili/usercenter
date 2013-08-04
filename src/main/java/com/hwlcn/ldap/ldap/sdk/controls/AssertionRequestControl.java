package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.ArrayList;
import java.util.Collection;

import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



/**
 * This class provides an implementation of the LDAP assertion request control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4528.txt">RFC 4528</A>.  It
 * may be used in conjunction with an add, compare, delete, modify, modify DN,
 * or search operation.  The assertion control includes a search filter, and the
 * associated operation should only be allowed to continue if the target entry
 * matches the provided filter.  If the filter does not match the target entry,
 * then the operation should fail with an
 * {@link ResultCode#ASSERTION_FAILED} result.
 * <BR><BR>
 * The behavior of the assertion request control makes it ideal for atomic
 * "check and set" types of operations, particularly when modifying an entry.
 * For example, it can be used to ensure that when changing the value of an
 * attribute, the current value has not been modified since it was last
 * retrieved.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the assertion request control.
 * It shows an attempt to modify an entry's "accountBalance" attribute to set
 * the value to "543.21" only if the current value is "1234.56":
 * <PRE>
 *   Modification mod = new Modification(ModificationType.REPLACE,
 *                                       "accountBalance", "543.21");
 *   ModifyRequest modifyRequest =
 *        new ModifyRequest("uid=john.doe,ou=People,dc=example,dc=com", mod);
 *   modifyRequest.addControl(
 *        new AssertionRequestControl("(accountBalance=1234.56)"));
 *
 *   try
 *   {
 *     LDAPResult modifyResult = connection.modify(modifyRequest);
 *     // If we've gotten here, then the modification was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     if (le.getResultCode() == ResultCode.ASSERTION_FAILED)
 *     {
 *       The modification failed because the accountBalance value wasn't what
 *       we thought it was.
 *     }
 *     else
 *     {
 *       The modification failed for some other reason.
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AssertionRequestControl
       extends Control
{

  public static final String ASSERTION_REQUEST_OID = "1.3.6.1.1.12";

  private static final long serialVersionUID = 6592634203410511095L;


  private final Filter filter;


  public AssertionRequestControl(final String filter)
         throws LDAPException
  {
    this(Filter.create(filter), true);
  }


  public AssertionRequestControl(final Filter filter)
  {
    this(filter, true);
  }

  public AssertionRequestControl(final String filter, final boolean isCritical)
         throws LDAPException
  {
    this(Filter.create(filter), isCritical);
  }

  public AssertionRequestControl(final Filter filter, final boolean isCritical)
  {
    super(ASSERTION_REQUEST_OID, isCritical, encodeValue(filter));

    this.filter = filter;
  }

  public AssertionRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ASSERT_NO_VALUE.get());
    }


    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      filter = Filter.decode(valueElement);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ASSERT_CANNOT_DECODE.get(e), e);
    }
  }


  public static AssertionRequestControl generate(final Entry sourceEntry,
                                                 final String... attributes)
  {
    Validator.ensureNotNull(sourceEntry);

    final ArrayList<Filter> andComponents;

    if ((attributes == null) || (attributes.length == 0))
    {
      final Collection<Attribute> entryAttrs = sourceEntry.getAttributes();
      andComponents = new ArrayList<Filter>(entryAttrs.size());
      for (final Attribute a : entryAttrs)
      {
        for (final ASN1OctetString v : a.getRawValues())
        {
          andComponents.add(Filter.createEqualityFilter(a.getName(),
               v.getValue()));
        }
      }
    }
    else
    {
      andComponents = new ArrayList<Filter>(attributes.length);
      for (final String name : attributes)
      {
        final Attribute a = sourceEntry.getAttribute(name);
        if (a != null)
        {
          for (final ASN1OctetString v : a.getRawValues())
          {
            andComponents.add(Filter.createEqualityFilter(name, v.getValue()));
          }
        }
      }
    }

    if (andComponents.size() == 1)
    {
      return new AssertionRequestControl(andComponents.get(0));
    }
    else
    {
      return new AssertionRequestControl(Filter.createANDFilter(andComponents));
    }
  }


  private static ASN1OctetString encodeValue(final Filter filter)
  {
    return new ASN1OctetString(filter.encode().encode());
  }

  public Filter getFilter()
  {
    return filter;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ASSERTION_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AssertionRequestControl(filter='");
    filter.toString(buffer);
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
