package com.hwlcn.ldap.ldap.sdk;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1BufferSet;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1Set;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSet;
import com.hwlcn.ldap.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.util.Base64;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Attribute
       implements Serializable
{

  private static final ASN1OctetString[] NO_VALUES = new ASN1OctetString[0];



  private static final byte[][] NO_BYTE_VALUES = new byte[0][];



  private static final long serialVersionUID = 5867076498293567612L;



  private final ASN1OctetString[] values;

  private int hashCode = -1;

  private final MatchingRule matchingRule;

  private final String name;




  public Attribute(final String name)
  {
    ensureNotNull(name);

    this.name = name;

    values = NO_VALUES;
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  public Attribute(final String name, final String value)
  {
    ensureNotNull(name, value);

    this.name = name;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  public Attribute(final String name, final byte[] value)
  {
    ensureNotNull(name, value);

    this.name = name;
    values = new ASN1OctetString[] { new ASN1OctetString(value) };
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }




  public Attribute(final String name, final String... values)
  {
    ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  public Attribute(final String name, final byte[]... values)
  {
    ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  public Attribute(final String name, final ASN1OctetString... values)
  {
    ensureNotNull(name, values);

    this.name   = name;
    this.values = values;

    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }




  public Attribute(final String name, final Collection<String> values)
  {
    ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.size()];

    int i=0;
    for (final String s : values)
    {
      this.values[i++] = new ASN1OctetString(s);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  public Attribute(final String name, final MatchingRule matchingRule)
  {
    ensureNotNull(name, matchingRule);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = NO_VALUES;
  }



  public Attribute(final String name, final MatchingRule matchingRule,
                   final String value)
  {
    ensureNotNull(name, matchingRule, value);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
  }




  public Attribute(final String name, final MatchingRule matchingRule,
                   final byte[] value)
  {
    ensureNotNull(name, matchingRule, value);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
  }




  public Attribute(final String name, final MatchingRule matchingRule,
                   final String... values)
  {
    ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
  }




  public Attribute(final String name, final MatchingRule matchingRule,
                   final byte[]... values)
  {
    ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
  }



  public Attribute(final String name, final MatchingRule matchingRule,
                   final Collection<String> values)
  {
    ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.size()];

    int i=0;
    for (final String s : values)
    {
      this.values[i++] = new ASN1OctetString(s);
    }
  }




  public Attribute(final String name, final MatchingRule matchingRule,
                   final ASN1OctetString[] values)
  {
    this.name         = name;
    this.matchingRule = matchingRule;
    this.values       = values;
  }




  public Attribute(final String name, final Schema schema,
                   final String... values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  public Attribute(final String name, final Schema schema,
                   final byte[]... values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  public Attribute(final String name, final Schema schema,
                   final Collection<String> values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  public Attribute(final String name, final Schema schema,
                   final ASN1OctetString[] values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  public static Attribute mergeAttributes(final Attribute attr1,
                                          final Attribute attr2)
  {
    ensureNotNull(attr1, attr2);

    final String name = attr1.name;
    ensureTrue(name.equalsIgnoreCase(attr2.name));

    final MatchingRule matchingRule = attr1.matchingRule;

    ASN1OctetString[] mergedValues =
         new ASN1OctetString[attr1.values.length + attr2.values.length];
    System.arraycopy(attr1.values, 0, mergedValues, 0, attr1.values.length);

    int pos = attr1.values.length;
    for (final ASN1OctetString s2 : attr2.values)
    {
      boolean found = false;
      for (final ASN1OctetString s1 : attr1.values)
      {
        try
        {
          if (matchingRule.valuesMatch(s1, s2))
          {
            found = true;
            break;
          }
        }
        catch (Exception e)
        {
          debugException(e);
        }
      }

      if (! found)
      {
        mergedValues[pos++] = s2;
      }
    }

    if (pos != mergedValues.length)
    {
      final ASN1OctetString[] newMergedValues = new ASN1OctetString[pos];
      System.arraycopy(mergedValues, 0, newMergedValues, 0, pos);
      mergedValues = newMergedValues;
    }

    return new Attribute(name, matchingRule, mergedValues);
  }




  public static Attribute removeValues(final Attribute attr1,
                                       final Attribute attr2)
  {
    return removeValues(attr1, attr2, attr1.matchingRule);
  }



  public static Attribute removeValues(final Attribute attr1,
                                       final Attribute attr2,
                                       final MatchingRule matchingRule)
  {
    ensureNotNull(attr1, attr2);

    final String name = attr1.name;
    ensureTrue(name.equalsIgnoreCase(attr2.name));

    final MatchingRule mr;
    if (matchingRule == null)
    {
      mr = attr1.matchingRule;
    }
    else
    {
      mr = matchingRule;
    }

    final ArrayList<ASN1OctetString> newValues =
         new ArrayList<ASN1OctetString>(Arrays.asList(attr1.values));

    final Iterator<ASN1OctetString> iterator = newValues.iterator();
    while (iterator.hasNext())
    {
      if (attr2.hasValue(iterator.next(), mr))
      {
        iterator.remove();
      }
    }

    final ASN1OctetString[] newValueArray =
         new ASN1OctetString[newValues.size()];
    newValues.toArray(newValueArray);

    return new Attribute(name, mr, newValueArray);
  }



  public String getName()
  {
    return name;
  }




  public String getBaseName()
  {
    return getBaseName(name);
  }




  public static String getBaseName(final String name)
  {
    final int semicolonPos = name.indexOf(';');
    if (semicolonPos > 0)
    {
      return name.substring(0, semicolonPos);
    }
    else
    {
      return name;
    }
  }




  public boolean nameIsValid()
  {
    return nameIsValid(name, true);
  }

  public static boolean nameIsValid(final String s)
  {
    return nameIsValid(s, true);
  }

  public static boolean nameIsValid(final String s, final boolean allowOptions)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return false;
    }

    final char firstChar = s.charAt(0);
    if (! (((firstChar >= 'a') && (firstChar <= 'z')) ||
          ((firstChar >= 'A') && (firstChar <= 'Z'))))
    {
      return false;
    }

    boolean lastWasSemiColon = false;
    for (int i=1; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {
        lastWasSemiColon = false;
      }
      else if (((c >= '0') && (c <= '9')) ||
               (c == '-'))
      {

        if (lastWasSemiColon)
        {
          return false;
        }

        lastWasSemiColon = false;
      }
      else if (c == ';')
      {
        if (lastWasSemiColon || (! allowOptions))
        {
          return false;
        }

        lastWasSemiColon = true;
      }
      else
      {
        return false;
      }
    }

    return (! lastWasSemiColon);
  }


  public boolean hasOptions()
  {
    return hasOptions(name);
  }


  public static boolean hasOptions(final String name)
  {
    return (name.indexOf(';') > 0);
  }

  public boolean hasOption(final String option)
  {
    return hasOption(name, option);
  }


  public static boolean hasOption(final String name, final String option)
  {
    final Set<String> options = getOptions(name);
    for (final String s : options)
    {
      if (s.equalsIgnoreCase(option))
      {
        return true;
      }
    }

    return false;
  }


  public Set<String> getOptions()
  {
    return getOptions(name);
  }



  public static Set<String> getOptions(final String name)
  {
    int semicolonPos = name.indexOf(';');
    if (semicolonPos > 0)
    {
      final LinkedHashSet<String> options = new LinkedHashSet<String>();
      while (true)
      {
        final int nextSemicolonPos = name.indexOf(';', semicolonPos+1);
        if (nextSemicolonPos > 0)
        {
          options.add(name.substring(semicolonPos+1, nextSemicolonPos));
          semicolonPos = nextSemicolonPos;
        }
        else
        {
          options.add(name.substring(semicolonPos+1));
          break;
        }
      }

      return Collections.unmodifiableSet(options);
    }
    else
    {
      return Collections.emptySet();
    }
  }


  public MatchingRule getMatchingRule()
  {
    return matchingRule;
  }


  public String getValue()
  {
    if (values.length == 0)
    {
      return null;
    }

    return values[0].stringValue();
  }


  public byte[] getValueByteArray()
  {
    if (values.length == 0)
    {
      return null;
    }

    return values[0].getValue();
  }

  public Boolean getValueAsBoolean()
  {
    if (values.length == 0)
    {
      return null;
    }

    final String lowerValue = toLowerCase(values[0].stringValue());
    if (lowerValue.equals("true") || lowerValue.equals("t") ||
        lowerValue.equals("yes") || lowerValue.equals("y") ||
        lowerValue.equals("on") || lowerValue.equals("1"))
    {
      return Boolean.TRUE;
    }
    else if (lowerValue.equals("false") || lowerValue.equals("f") ||
             lowerValue.equals("no") || lowerValue.equals("n") ||
             lowerValue.equals("off") || lowerValue.equals("0"))
    {
      return Boolean.FALSE;
    }
    else
    {
      return null;
    }
  }

  public Date getValueAsDate()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return decodeGeneralizedTime(values[0].stringValue());
    }
    catch (Exception e)
    {
      debugException(e);
      return null;
    }
  }


  public DN getValueAsDN()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return new DN(values[0].stringValue());
    }
    catch (Exception e)
    {
      debugException(e);
      return null;
    }
  }


  public Integer getValueAsInteger()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return Integer.valueOf(values[0].stringValue());
    }
    catch (NumberFormatException nfe)
    {
      debugException(nfe);
      return null;
    }
  }

  public Long getValueAsLong()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return Long.valueOf(values[0].stringValue());
    }
    catch (NumberFormatException nfe)
    {
      debugException(nfe);
      return null;
    }
  }

  public String[] getValues()
  {
    if (values.length == 0)
    {
      return NO_STRINGS;
    }

    final String[] stringValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      stringValues[i] = values[i].stringValue();
    }

    return stringValues;
  }


  public byte[][] getValueByteArrays()
  {
    if (values.length == 0)
    {
      return NO_BYTE_VALUES;
    }

    final byte[][] byteValues = new byte[values.length][];
    for (int i=0; i < values.length; i++)
    {
      byteValues[i] = values[i].getValue();
    }

    return byteValues;
  }


  public ASN1OctetString[] getRawValues()
  {
    return values;
  }


  public boolean hasValue()
  {
    return (values.length > 0);
  }



  public boolean hasValue(final String value)
  {
    ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }


  public boolean hasValue(final String value, final MatchingRule matchingRule)
  {
    ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }


  public boolean hasValue(final byte[] value)
  {
    ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }



  public boolean hasValue(final byte[] value, final MatchingRule matchingRule)
  {
    ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }


  boolean hasValue(final ASN1OctetString value)
  {
    return hasValue(value, matchingRule);
  }


  boolean hasValue(final ASN1OctetString value, final MatchingRule matchingRule)
  {
    for (final ASN1OctetString existingValue : values)
    {
      try
      {
        if (matchingRule.valuesMatch(existingValue, value))
        {
          return true;
        }
      }
      catch (final LDAPException le)
      {
        debugException(le);

        if (existingValue.equals(value))
        {
          return true;
        }
      }
    }
    return false;
  }

  public int size()
  {
    return values.length;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    buffer.addOctetString(name);

    final ASN1BufferSet valueSet = buffer.beginSet();
    for (final ASN1OctetString value : values)
    {
      buffer.addElement(value);
    }
    valueSet.end();
    attrSequence.end();
  }


  public ASN1Sequence encode()
  {
    final ASN1Element[] elements =
    {
      new ASN1OctetString(name),
      new ASN1Set(values)
    };

    return new ASN1Sequence(elements);
  }

  public static Attribute readFrom(final ASN1StreamReader reader)
         throws LDAPException
  {
    return readFrom(reader, null);
  }


  public static Attribute readFrom(final ASN1StreamReader reader,
                                   final Schema schema)
         throws LDAPException
  {
    try
    {
      ensureNotNull(reader.beginSequence());
      final String attrName = reader.readString();
      ensureNotNull(attrName);

      final MatchingRule matchingRule =
           MatchingRule.selectEqualityMatchingRule(attrName, schema);

      final ArrayList<ASN1OctetString> valueList =
           new ArrayList<ASN1OctetString>();
      final ASN1StreamReaderSet valueSet = reader.beginSet();
      while (valueSet.hasMoreElements())
      {
        valueList.add(new ASN1OctetString(reader.readBytes()));
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      return new Attribute(attrName, matchingRule, values);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ATTR_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public static Attribute decode(final ASN1Sequence encodedAttribute)
         throws LDAPException
  {
    ensureNotNull(encodedAttribute);

    final ASN1Element[] elements = encodedAttribute.elements();
    if (elements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_ATTR_DECODE_INVALID_COUNT.get(elements.length));
    }

    final String name =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    final ASN1Set valueSet;
    try
    {
      valueSet = ASN1Set.decodeAsSet(elements[1]);
    }
    catch (ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ATTR_DECODE_VALUE_SET.get(getExceptionMessage(ae)), ae);
    }

    final ASN1OctetString[] values =
         new ASN1OctetString[valueSet.elements().length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = ASN1OctetString.decodeAsOctetString(valueSet.elements()[i]);
    }

    return new Attribute(name, CaseIgnoreStringMatchingRule.getInstance(),
                         values);
  }

  public boolean needsBase64Encoding()
  {
    for (final ASN1OctetString v : values)
    {
      if (needsBase64Encoding(v.getValue()))
      {
        return true;
      }
    }

    return false;
  }

  public static boolean needsBase64Encoding(final String v)
  {
    return needsBase64Encoding(getBytes(v));
  }


  public static boolean needsBase64Encoding(final byte[] v)
  {
    if (v.length == 0)
    {
      return false;
    }

    switch (v[0] & 0xFF)
    {
      case 0x20:
      case 0x3A:
      case 0x3C:
        return true;
    }

    if ((v[v.length-1] & 0xFF) == 0x20)
    {
      return true;
    }

    for (final byte b : v)
    {
      switch (b & 0xFF)
      {
        case 0x00:
        case 0x0A:
        case 0x0D:
          return true;

        default:
          if ((b & 0x80) != 0x00)
          {
            return true;
          }
          break;
      }
    }

    return false;
  }

  @Override()
  public int hashCode()
  {
    if (hashCode == -1)
    {
      int c = toLowerCase(name).hashCode();

      for (final ASN1OctetString value : values)
      {
        try
        {
          c += matchingRule.normalize(value).hashCode();
        }
        catch (LDAPException le)
        {
          debugException(le);
          c += value.hashCode();
        }
      }

      hashCode = c;
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

    if (! (o instanceof Attribute))
    {
      return false;
    }

    final Attribute a = (Attribute) o;
    if (! name.equalsIgnoreCase(a.name))
    {
      return false;
    }

    if (values.length != a.values.length)
    {
      return false;
    }

    if (values.length > 10)
    {

      final HashSet<ASN1OctetString> unNormalizedValues =
           new HashSet<ASN1OctetString>(values.length);
      Collections.addAll(unNormalizedValues, values);

      HashSet<ASN1OctetString> normalizedMissingValues = null;
      for (final ASN1OctetString value : a.values)
      {
        if (! unNormalizedValues.remove(value))
        {
          if (normalizedMissingValues == null)
          {
            normalizedMissingValues =
                 new HashSet<ASN1OctetString>(values.length);
          }

          try
          {
            normalizedMissingValues.add(matchingRule.normalize(value));
          }
          catch (final Exception e)
          {
            debugException(e);
            return false;
          }
        }
      }

      if (normalizedMissingValues != null)
      {
        for (final ASN1OctetString value : unNormalizedValues)
        {
          try
          {
            if (! normalizedMissingValues.contains(
                       matchingRule.normalize(value)))
            {
              return false;
            }
          }
          catch (final Exception e)
          {
            debugException(e);
            return false;
          }
        }
      }
    }
    else
    {
      for (final ASN1OctetString value : values)
      {
        if (! a.hasValue(value))
        {
          return false;
        }
      }
    }

    return true;
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("Attribute(name=");
    buffer.append(name);

    if (values.length == 0)
    {
      buffer.append(", values={");
    }
    else if (needsBase64Encoding())
    {
      buffer.append(", base64Values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(Base64.encode(values[i].getValue()));
      }

      buffer.append('\'');
    }
    else
    {
      buffer.append(", values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(values[i].stringValue());
      }

      buffer.append('\'');
    }

    buffer.append("})");
  }
}
