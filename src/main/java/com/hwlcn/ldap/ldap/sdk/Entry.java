package com.hwlcn.ldap.ldap.sdk;


import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.ldap.ldif.LDIFReader;
import com.hwlcn.ldap.ldif.LDIFRecord;
import com.hwlcn.ldap.ldif.LDIFWriter;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import java.math.BigInteger;
import java.util.*;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.debugException;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


/**
 * This class provides a data structure for holding information about an LDAP
 * entry.  An entry contains a distinguished name (DN) and a set of attributes.
 * An entry can be created from these components, and it can also be created
 * from its LDIF representation as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.  For example:
 * <BR><BR>
 * <PRE>
 * Entry entry = new Entry(
 * "dn: dc=example,dc=com",
 * "objectClass: top",
 * "objectClass: domain",
 * "dc: example");
 * </PRE>
 * <BR><BR>
 * This class also provides methods for retrieving the LDIF representation of
 * an entry, either as a single string or as an array of strings that make up
 * the LDIF lines.
 * <BR><BR>
 * The {@link com.hwlcn.ldap.ldap.sdk.Entry#diff} method may be used to obtain the set of differences
 * between two entries, and to retrieve a list of {@link Modification} objects
 * that can be used to modify one entry so that it contains the same set of
 * data as another.  The {@link com.hwlcn.ldap.ldap.sdk.Entry#applyModifications} method may be used to
 * apply a set of modifications to an entry.
 * <BR><BR>
 * Entry objects are mutable, and the DN, set of attributes, and individual
 * attribute values can be altered.
 */
@Mutable()
@NotExtensible()
@ThreadSafety(level = ThreadSafetyLevel.NOT_THREADSAFE)
public class Entry
        implements LDIFRecord {

    private static final long serialVersionUID = -4438809025903729197L;

    private volatile DN parsedDN;

    private final LinkedHashMap<String, Attribute> attributes;

    private final Schema schema;

    private String dn;


    public Entry(final String dn) {
        this(dn, (Schema) null);
    }


    public Entry(final String dn, final Schema schema) {
        ensureNotNull(dn);

        this.dn = dn;
        this.schema = schema;

        attributes = new LinkedHashMap<String, Attribute>();
    }


    public Entry(final DN dn) {
        this(dn, (Schema) null);
    }


    public Entry(final DN dn, final Schema schema) {
        ensureNotNull(dn);

        parsedDN = dn;
        this.dn = parsedDN.toString();
        this.schema = schema;

        attributes = new LinkedHashMap<String, Attribute>();
    }


    public Entry(final String dn, final Attribute... attributes) {
        this(dn, null, attributes);
    }


    public Entry(final String dn, final Schema schema,
                 final Attribute... attributes) {
        ensureNotNull(dn, attributes);

        this.dn = dn;
        this.schema = schema;

        this.attributes = new LinkedHashMap<String, Attribute>(attributes.length);
        for (final Attribute a : attributes) {
            final String name = toLowerCase(a.getName());
            final Attribute attr = this.attributes.get(name);
            if (attr == null) {
                this.attributes.put(name, a);
            } else {
                this.attributes.put(name, Attribute.mergeAttributes(attr, a));
            }
        }
    }


    public Entry(final DN dn, final Attribute... attributes) {
        this(dn, null, attributes);
    }


    public Entry(final DN dn, final Schema schema, final Attribute... attributes) {
        ensureNotNull(dn, attributes);

        parsedDN = dn;
        this.dn = parsedDN.toString();
        this.schema = schema;

        this.attributes = new LinkedHashMap<String, Attribute>(attributes.length);
        for (final Attribute a : attributes) {
            final String name = toLowerCase(a.getName());
            final Attribute attr = this.attributes.get(name);
            if (attr == null) {
                this.attributes.put(name, a);
            } else {
                this.attributes.put(name, Attribute.mergeAttributes(attr, a));
            }
        }
    }


    public Entry(final String dn, final Collection<Attribute> attributes) {
        this(dn, null, attributes);
    }


    public Entry(final String dn, final Schema schema,
                 final Collection<Attribute> attributes) {
        ensureNotNull(dn, attributes);

        this.dn = dn;
        this.schema = schema;

        this.attributes = new LinkedHashMap<String, Attribute>(attributes.size());
        for (final Attribute a : attributes) {
            final String name = toLowerCase(a.getName());
            final Attribute attr = this.attributes.get(name);
            if (attr == null) {
                this.attributes.put(name, a);
            } else {
                this.attributes.put(name, Attribute.mergeAttributes(attr, a));
            }
        }
    }


    public Entry(final DN dn, final Collection<Attribute> attributes) {
        this(dn, null, attributes);
    }


    public Entry(final DN dn, final Schema schema,
                 final Collection<Attribute> attributes) {
        ensureNotNull(dn, attributes);

        parsedDN = dn;
        this.dn = parsedDN.toString();
        this.schema = schema;

        this.attributes = new LinkedHashMap<String, Attribute>(attributes.size());
        for (final Attribute a : attributes) {
            final String name = toLowerCase(a.getName());
            final Attribute attr = this.attributes.get(name);
            if (attr == null) {
                this.attributes.put(name, a);
            } else {
                this.attributes.put(name, Attribute.mergeAttributes(attr, a));
            }
        }
    }


    public Entry(final String... entryLines)
            throws LDIFException {
        this(null, entryLines);
    }


    public Entry(final Schema schema, final String... entryLines)
            throws LDIFException {
        final Entry e = LDIFReader.decodeEntry(entryLines);

        this.schema = schema;

        dn = e.dn;
        parsedDN = e.parsedDN;
        attributes = e.attributes;
    }


    public final String getDN() {
        return dn;
    }


    public void setDN(final String dn) {
        ensureNotNull(dn);

        this.dn = dn;
        parsedDN = null;
    }


    public void setDN(final DN dn) {
        ensureNotNull(dn);

        parsedDN = dn;
        this.dn = parsedDN.toString();
    }


    public final DN getParsedDN()
            throws LDAPException {
        if (parsedDN == null) {
            parsedDN = new DN(dn, schema);
        }

        return parsedDN;
    }


    public final RDN getRDN()
            throws LDAPException {
        return getParsedDN().getRDN();
    }


    public final DN getParentDN()
            throws LDAPException {
        if (parsedDN == null) {
            parsedDN = new DN(dn, schema);
        }

        return parsedDN.getParent();
    }

    public final String getParentDNString()
            throws LDAPException {
        if (parsedDN == null) {
            parsedDN = new DN(dn, schema);
        }

        final DN parentDN = parsedDN.getParent();
        if (parentDN == null) {
            return null;
        } else {
            return parentDN.toString();
        }
    }


    protected Schema getSchema() {
        return schema;
    }


    public final boolean hasAttribute(final String attributeName) {
        return hasAttribute(attributeName, schema);
    }


    public final boolean hasAttribute(final String attributeName,
                                      final Schema schema) {
        ensureNotNull(attributeName);

        if (attributes.containsKey(toLowerCase(attributeName))) {
            return true;
        }

        if (schema != null) {
            final String baseName;
            final String options;
            final int semicolonPos = attributeName.indexOf(';');
            if (semicolonPos > 0) {
                baseName = attributeName.substring(0, semicolonPos);
                options = toLowerCase(attributeName.substring(semicolonPos));
            } else {
                baseName = attributeName;
                options = "";
            }

            final AttributeTypeDefinition at = schema.getAttributeType(baseName);
            if (at != null) {
                if (attributes.containsKey(toLowerCase(at.getOID()) + options)) {
                    return true;
                }

                for (final String name : at.getNames()) {
                    if (attributes.containsKey(toLowerCase(name) + options)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }


    public final boolean hasAttribute(final Attribute attribute) {
        ensureNotNull(attribute);

        final String lowerName = toLowerCase(attribute.getName());
        final Attribute attr = attributes.get(lowerName);
        return ((attr != null) && attr.equals(attribute));
    }


    public final boolean hasAttributeValue(final String attributeName,
                                           final String attributeValue) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = attributes.get(toLowerCase(attributeName));
        return ((attr != null) && attr.hasValue(attributeValue));
    }


    public final boolean hasAttributeValue(final String attributeName,
                                           final String attributeValue,
                                           final MatchingRule matchingRule) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = attributes.get(toLowerCase(attributeName));
        return ((attr != null) && attr.hasValue(attributeValue, matchingRule));
    }


    public final boolean hasAttributeValue(final String attributeName,
                                           final byte[] attributeValue) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = attributes.get(toLowerCase(attributeName));
        return ((attr != null) && attr.hasValue(attributeValue));
    }


    public final boolean hasAttributeValue(final String attributeName,
                                           final byte[] attributeValue,
                                           final MatchingRule matchingRule) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = attributes.get(toLowerCase(attributeName));
        return ((attr != null) && attr.hasValue(attributeValue, matchingRule));
    }


    public final boolean hasObjectClass(final String objectClassName) {
        return hasAttributeValue("objectClass", objectClassName);
    }


    public final Collection<Attribute> getAttributes() {
        return Collections.unmodifiableCollection(attributes.values());
    }


    public final Attribute getAttribute(final String attributeName) {
        return getAttribute(attributeName, schema);
    }


    public final Attribute getAttribute(final String attributeName,
                                        final Schema schema) {
        ensureNotNull(attributeName);

        Attribute a = attributes.get(toLowerCase(attributeName));
        if ((a == null) && (schema != null)) {
            final String baseName;
            final String options;
            final int semicolonPos = attributeName.indexOf(';');
            if (semicolonPos > 0) {
                baseName = attributeName.substring(0, semicolonPos);
                options = toLowerCase(attributeName.substring(semicolonPos));
            } else {
                baseName = attributeName;
                options = "";
            }

            final AttributeTypeDefinition at = schema.getAttributeType(baseName);
            if (at == null) {
                return null;
            }

            a = attributes.get(toLowerCase(at.getOID() + options));
            if (a == null) {
                for (final String name : at.getNames()) {
                    a = attributes.get(toLowerCase(name) + options);
                    if (a != null) {
                        return a;
                    }
                }
            }

            return a;
        } else {
            return a;
        }
    }


    public final List<Attribute> getAttributesWithOptions(final String baseName,
                                                          final Set<String> options) {
        ensureNotNull(baseName);

        final ArrayList<Attribute> attrList = new ArrayList<Attribute>(10);

        for (final Attribute a : attributes.values()) {
            if (a.getBaseName().equalsIgnoreCase(baseName)) {
                if ((options == null) || options.isEmpty()) {
                    attrList.add(a);
                } else {
                    boolean allFound = true;
                    for (final String option : options) {
                        if (!a.hasOption(option)) {
                            allFound = false;
                            break;
                        }
                    }

                    if (allFound) {
                        attrList.add(a);
                    }
                }
            }
        }

        return Collections.unmodifiableList(attrList);
    }


    public String getAttributeValue(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValue();
        }
    }


    public byte[] getAttributeValueBytes(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueByteArray();
        }
    }


    public Boolean getAttributeValueAsBoolean(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueAsBoolean();
        }
    }


    public Date getAttributeValueAsDate(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueAsDate();
        }
    }


    public DN getAttributeValueAsDN(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueAsDN();
        }
    }


    public Integer getAttributeValueAsInteger(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueAsInteger();
        }
    }


    public Long getAttributeValueAsLong(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueAsLong();
        }
    }


    public String[] getAttributeValues(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValues();
        }
    }


    public byte[][] getAttributeValueByteArrays(final String attributeName) {
        ensureNotNull(attributeName);

        final Attribute a = attributes.get(toLowerCase(attributeName));
        if (a == null) {
            return null;
        } else {
            return a.getValueByteArrays();
        }
    }


    public final Attribute getObjectClassAttribute() {
        return getAttribute("objectClass");
    }


    public final String[] getObjectClassValues() {
        return getAttributeValues("objectClass");
    }


    public boolean addAttribute(final Attribute attribute) {
        ensureNotNull(attribute);

        final String lowerName = toLowerCase(attribute.getName());
        final Attribute attr = attributes.get(lowerName);
        if (attr == null) {
            attributes.put(lowerName, attribute);
            return true;
        } else {
            final Attribute newAttr = Attribute.mergeAttributes(attr, attribute);
            attributes.put(lowerName, newAttr);
            return (attr.getRawValues().length != newAttr.getRawValues().length);
        }
    }


    public boolean addAttribute(final String attributeName,
                                final String attributeValue) {
        ensureNotNull(attributeName, attributeValue);
        return addAttribute(new Attribute(attributeName, schema, attributeValue));
    }


    public boolean addAttribute(final String attributeName,
                                final byte[] attributeValue) {
        ensureNotNull(attributeName, attributeValue);
        return addAttribute(new Attribute(attributeName, schema, attributeValue));
    }


    public boolean addAttribute(final String attributeName,
                                final String... attributeValues) {
        ensureNotNull(attributeName, attributeValues);
        return addAttribute(new Attribute(attributeName, schema, attributeValues));
    }


    public boolean addAttribute(final String attributeName,
                                final byte[]... attributeValues) {
        ensureNotNull(attributeName, attributeValues);
        return addAttribute(new Attribute(attributeName, schema, attributeValues));
    }


    public boolean removeAttribute(final String attributeName) {
        ensureNotNull(attributeName);

        if (schema == null) {
            return (attributes.remove(toLowerCase(attributeName)) != null);
        } else {
            final Attribute a = getAttribute(attributeName, schema);
            if (a == null) {
                return false;
            } else {
                attributes.remove(toLowerCase(a.getName()));
                return true;
            }
        }
    }


    public boolean removeAttributeValue(final String attributeName,
                                        final String attributeValue) {
        return removeAttributeValue(attributeName, attributeValue, null);
    }


    public boolean removeAttributeValue(final String attributeName,
                                        final String attributeValue,
                                        final MatchingRule matchingRule) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = getAttribute(attributeName, schema);
        if (attr == null) {
            return false;
        } else {
            final String lowerName = toLowerCase(attr.getName());
            final Attribute newAttr = Attribute.removeValues(attr,
                    new Attribute(attributeName, attributeValue), matchingRule);
            if (newAttr.hasValue()) {
                attributes.put(lowerName, newAttr);
            } else {
                attributes.remove(lowerName);
            }

            return (attr.getRawValues().length != newAttr.getRawValues().length);
        }
    }


    public boolean removeAttributeValue(final String attributeName,
                                        final byte[] attributeValue) {
        return removeAttributeValue(attributeName, attributeValue, null);
    }


    public boolean removeAttributeValue(final String attributeName,
                                        final byte[] attributeValue,
                                        final MatchingRule matchingRule) {
        ensureNotNull(attributeName, attributeValue);

        final Attribute attr = getAttribute(attributeName, schema);
        if (attr == null) {
            return false;
        } else {
            final String lowerName = toLowerCase(attr.getName());
            final Attribute newAttr = Attribute.removeValues(attr,
                    new Attribute(attributeName, attributeValue), matchingRule);
            if (newAttr.hasValue()) {
                attributes.put(lowerName, newAttr);
            } else {
                attributes.remove(lowerName);
            }

            return (attr.getRawValues().length != newAttr.getRawValues().length);
        }
    }


    public boolean removeAttributeValues(final String attributeName,
                                         final String... attributeValues) {
        ensureNotNull(attributeName, attributeValues);

        final Attribute attr = getAttribute(attributeName, schema);
        if (attr == null) {
            return false;
        } else {
            final String lowerName = toLowerCase(attr.getName());
            final Attribute newAttr = Attribute.removeValues(attr,
                    new Attribute(attributeName, attributeValues));
            if (newAttr.hasValue()) {
                attributes.put(lowerName, newAttr);
            } else {
                attributes.remove(lowerName);
            }

            return (attr.getRawValues().length != newAttr.getRawValues().length);
        }
    }


    public boolean removeAttributeValues(final String attributeName,
                                         final byte[]... attributeValues) {
        ensureNotNull(attributeName, attributeValues);

        final Attribute attr = getAttribute(attributeName, schema);
        if (attr == null) {
            return false;
        } else {
            final String lowerName = toLowerCase(attr.getName());
            final Attribute newAttr = Attribute.removeValues(attr,
                    new Attribute(attributeName, attributeValues));
            if (newAttr.hasValue()) {
                attributes.put(lowerName, newAttr);
            } else {
                attributes.remove(lowerName);
            }

            return (attr.getRawValues().length != newAttr.getRawValues().length);
        }
    }


    public void setAttribute(final Attribute attribute) {
        ensureNotNull(attribute);

        final String lowerName;
        final Attribute a = getAttribute(attribute.getName(), schema);
        if (a == null) {
            lowerName = toLowerCase(attribute.getName());
        } else {
            lowerName = toLowerCase(a.getName());
        }

        attributes.put(lowerName, attribute);
    }


    public void setAttribute(final String attributeName,
                             final String attributeValue) {
        ensureNotNull(attributeName, attributeValue);
        setAttribute(new Attribute(attributeName, schema, attributeValue));
    }


    public void setAttribute(final String attributeName,
                             final byte[] attributeValue) {
        ensureNotNull(attributeName, attributeValue);
        setAttribute(new Attribute(attributeName, schema, attributeValue));
    }


    public void setAttribute(final String attributeName,
                             final String... attributeValues) {
        ensureNotNull(attributeName, attributeValues);
        setAttribute(new Attribute(attributeName, schema, attributeValues));
    }


    public void setAttribute(final String attributeName,
                             final byte[]... attributeValues) {
        ensureNotNull(attributeName, attributeValues);
        setAttribute(new Attribute(attributeName, schema, attributeValues));
    }


    public boolean matchesBaseAndScope(final String baseDN,
                                       final SearchScope scope)
            throws LDAPException {
        return getParsedDN().matchesBaseAndScope(new DN(baseDN), scope);
    }


    public boolean matchesBaseAndScope(final DN baseDN, final SearchScope scope)
            throws LDAPException {
        return getParsedDN().matchesBaseAndScope(baseDN, scope);
    }

    public static List<Modification> diff(final Entry sourceEntry,
                                          final Entry targetEntry,
                                          final boolean ignoreRDN,
                                          final String... attributes) {
        return diff(sourceEntry, targetEntry, ignoreRDN, true, attributes);
    }


    public static List<Modification> diff(final Entry sourceEntry,
                                          final Entry targetEntry,
                                          final boolean ignoreRDN,
                                          final boolean reversible,
                                          final String... attributes) {
        HashSet<String> compareAttrs = null;
        if ((attributes != null) && (attributes.length > 0)) {
            compareAttrs = new HashSet<String>(attributes.length);
            for (final String s : attributes) {
                compareAttrs.add(toLowerCase(s));
            }
        }

        final LinkedHashMap<String, Attribute> sourceOnlyAttrs =
                new LinkedHashMap<String, Attribute>();
        final LinkedHashMap<String, Attribute> targetOnlyAttrs =
                new LinkedHashMap<String, Attribute>();
        final LinkedHashMap<String, Attribute> commonAttrs =
                new LinkedHashMap<String, Attribute>();

        for (final Map.Entry<String, Attribute> e :
                sourceEntry.attributes.entrySet()) {
            final String lowerName = toLowerCase(e.getKey());
            if ((compareAttrs != null) && (!compareAttrs.contains(lowerName))) {
                continue;
            }

            sourceOnlyAttrs.put(lowerName, e.getValue());
            commonAttrs.put(lowerName, e.getValue());
        }

        for (final Map.Entry<String, Attribute> e :
                targetEntry.attributes.entrySet()) {
            final String lowerName = toLowerCase(e.getKey());
            if ((compareAttrs != null) && (!compareAttrs.contains(lowerName))) {
                continue;
            }


            if (sourceOnlyAttrs.remove(lowerName) == null) {
                targetOnlyAttrs.put(lowerName, e.getValue());
            }
        }

        for (final String lowerName : sourceOnlyAttrs.keySet()) {
            commonAttrs.remove(lowerName);
        }

        RDN sourceRDN = null;
        RDN targetRDN = null;
        if (ignoreRDN) {
            try {
                sourceRDN = sourceEntry.getRDN();
            } catch (Exception e) {
                debugException(e);
            }

            try {
                targetRDN = targetEntry.getRDN();
            } catch (Exception e) {
                debugException(e);
            }
        }

        final ArrayList<Modification> mods = new ArrayList<Modification>(10);

        for (final Attribute a : sourceOnlyAttrs.values()) {
            if (reversible) {
                ASN1OctetString[] values = a.getRawValues();
                if ((sourceRDN != null) && (sourceRDN.hasAttribute(a.getName()))) {
                    final ArrayList<ASN1OctetString> newValues =
                            new ArrayList<ASN1OctetString>(values.length);
                    for (final ASN1OctetString value : values) {
                        if (!sourceRDN.hasAttributeValue(a.getName(), value.getValue())) {
                            newValues.add(value);
                        }
                    }

                    if (newValues.isEmpty()) {
                        continue;
                    } else {
                        values = new ASN1OctetString[newValues.size()];
                        newValues.toArray(values);
                    }
                }

                mods.add(new Modification(ModificationType.DELETE, a.getName(),
                        values));
            } else {
                mods.add(new Modification(ModificationType.REPLACE, a.getName()));
            }
        }

        for (final Attribute a : targetOnlyAttrs.values()) {
            ASN1OctetString[] values = a.getRawValues();
            if ((targetRDN != null) && (targetRDN.hasAttribute(a.getName()))) {
                final ArrayList<ASN1OctetString> newValues =
                        new ArrayList<ASN1OctetString>(values.length);
                for (final ASN1OctetString value : values) {
                    if (!targetRDN.hasAttributeValue(a.getName(), value.getValue())) {
                        newValues.add(value);
                    }
                }

                if (newValues.isEmpty()) {
                    continue;
                } else {
                    values = new ASN1OctetString[newValues.size()];
                    newValues.toArray(values);
                }
            }

            if (reversible) {
                mods.add(new Modification(ModificationType.ADD, a.getName(), values));
            } else {
                mods.add(new Modification(ModificationType.REPLACE, a.getName(),
                        values));
            }
        }

        for (final Attribute sourceAttr : commonAttrs.values()) {
            final Attribute targetAttr =
                    targetEntry.getAttribute(sourceAttr.getName());
            if (sourceAttr.equals(targetAttr)) {
                continue;
            }

            if (reversible ||
                    ((targetRDN != null) && targetRDN.hasAttribute(targetAttr.getName()))) {
                final ASN1OctetString[] sourceValueArray = sourceAttr.getRawValues();
                final LinkedHashMap<ASN1OctetString, ASN1OctetString> sourceValues =
                        new LinkedHashMap<ASN1OctetString, ASN1OctetString>(
                                sourceValueArray.length);
                for (final ASN1OctetString s : sourceValueArray) {
                    try {
                        sourceValues.put(sourceAttr.getMatchingRule().normalize(s), s);
                    } catch (final Exception e) {
                        debugException(e);
                        sourceValues.put(s, s);
                    }
                }

                final ASN1OctetString[] targetValueArray = targetAttr.getRawValues();
                final LinkedHashMap<ASN1OctetString, ASN1OctetString> targetValues =
                        new LinkedHashMap<ASN1OctetString, ASN1OctetString>(
                                targetValueArray.length);
                for (final ASN1OctetString s : targetValueArray) {
                    try {
                        targetValues.put(sourceAttr.getMatchingRule().normalize(s), s);
                    } catch (final Exception e) {
                        debugException(e);
                        targetValues.put(s, s);
                    }
                }

                final Iterator<Map.Entry<ASN1OctetString, ASN1OctetString>>
                        sourceIterator = sourceValues.entrySet().iterator();
                while (sourceIterator.hasNext()) {
                    final Map.Entry<ASN1OctetString, ASN1OctetString> e =
                            sourceIterator.next();
                    if (targetValues.remove(e.getKey()) != null) {
                        sourceIterator.remove();
                    } else if ((sourceRDN != null) &&
                            sourceRDN.hasAttributeValue(sourceAttr.getName(),
                                    e.getValue().getValue())) {
                        sourceIterator.remove();
                    }
                }

                final Iterator<Map.Entry<ASN1OctetString, ASN1OctetString>>
                        targetIterator = targetValues.entrySet().iterator();
                while (targetIterator.hasNext()) {
                    final Map.Entry<ASN1OctetString, ASN1OctetString> e =
                            targetIterator.next();
                    if ((targetRDN != null) &&
                            targetRDN.hasAttributeValue(targetAttr.getName(),
                                    e.getValue().getValue())) {
                        targetIterator.remove();
                    }
                }

                final ArrayList<ASN1OctetString> addValues =
                        new ArrayList<ASN1OctetString>(targetValues.values());
                final ArrayList<ASN1OctetString> delValues =
                        new ArrayList<ASN1OctetString>(sourceValues.values());

                if (!addValues.isEmpty()) {
                    final ASN1OctetString[] addArray =
                            new ASN1OctetString[addValues.size()];
                    mods.add(new Modification(ModificationType.ADD, targetAttr.getName(),
                            addValues.toArray(addArray)));
                }

                if (!delValues.isEmpty()) {
                    final ASN1OctetString[] delArray =
                            new ASN1OctetString[delValues.size()];
                    mods.add(new Modification(ModificationType.DELETE,
                            sourceAttr.getName(), delValues.toArray(delArray)));
                }
            } else {
                mods.add(new Modification(ModificationType.REPLACE,
                        targetAttr.getName(), targetAttr.getRawValues()));
            }
        }

        return mods;
    }


    public static Entry mergeEntries(final Entry... entries) {
        ensureNotNull(entries);
        ensureTrue(entries.length > 0);

        final Entry newEntry = entries[0].duplicate();

        for (int i = 1; i < entries.length; i++) {
            for (final Attribute a : entries[i].attributes.values()) {
                newEntry.addAttribute(a);
            }
        }

        return newEntry;
    }


    public static Entry intersectEntries(final Entry... entries) {
        ensureNotNull(entries);
        ensureTrue(entries.length > 0);

        final Entry newEntry = entries[0].duplicate();

        for (final Attribute a : entries[0].attributes.values()) {
            final String name = a.getName();
            for (final byte[] v : a.getValueByteArrays()) {
                for (int i = 1; i < entries.length; i++) {
                    if (!entries[i].hasAttributeValue(name, v)) {
                        newEntry.removeAttributeValue(name, v);
                        break;
                    }
                }
            }
        }

        return newEntry;
    }


    public static Entry applyModifications(final Entry entry,
                                           final boolean lenient,
                                           final Modification... modifications)
            throws LDAPException {
        ensureNotNull(entry, modifications);
        ensureFalse(modifications.length == 0);

        return applyModifications(entry, lenient, Arrays.asList(modifications));
    }


    public static Entry applyModifications(final Entry entry,
                                           final boolean lenient,
                                           final List<Modification> modifications)
            throws LDAPException {
        ensureNotNull(entry, modifications);
        ensureFalse(modifications.isEmpty());

        final Entry e = entry.duplicate();
        final ArrayList<String> errors =
                new ArrayList<String>(modifications.size());
        ResultCode resultCode = null;

        RDN rdn = null;
        try {
            rdn = entry.getRDN();
        } catch (final LDAPException le) {
            debugException(le);
        }

        for (final Modification m : modifications) {
            final String name = m.getAttributeName();
            final byte[][] values = m.getValueByteArrays();
            switch (m.getModificationType().intValue()) {
                case ModificationType.ADD_INT_VALUE:
                    if (lenient) {
                        e.addAttribute(m.getAttribute());
                    } else {
                        if (values.length == 0) {
                            errors.add(ERR_ENTRY_APPLY_MODS_ADD_NO_VALUES.get(name));
                        }

                        for (int i = 0; i < values.length; i++) {
                            if (!e.addAttribute(name, values[i])) {
                                if (resultCode == null) {
                                    resultCode = ResultCode.ATTRIBUTE_OR_VALUE_EXISTS;
                                }
                                errors.add(ERR_ENTRY_APPLY_MODS_ADD_EXISTING.get(
                                        m.getValues()[i], name));
                            }
                        }
                    }
                    break;

                case ModificationType.DELETE_INT_VALUE:
                    if (values.length == 0) {
                        if ((rdn != null) && rdn.hasAttribute(name)) {
                            final String msg =
                                    ERR_ENTRY_APPLY_MODS_TARGETS_RDN.get(entry.getDN());
                            if (!errors.contains(msg)) {
                                errors.add(msg);
                            }

                            if (resultCode == null) {
                                resultCode = ResultCode.NOT_ALLOWED_ON_RDN;
                            }
                            break;
                        }

                        final boolean removed = e.removeAttribute(name);
                        if (!(lenient || removed)) {
                            if (resultCode == null) {
                                resultCode = ResultCode.NO_SUCH_ATTRIBUTE;
                            }
                            errors.add(ERR_ENTRY_APPLY_MODS_DELETE_NONEXISTENT_ATTR.get(
                                    name));
                        }
                    } else {
                        deleteValueLoop:
                        for (int i = 0; i < values.length; i++) {
                            if ((rdn != null) && rdn.hasAttributeValue(name, values[i])) {
                                final String msg =
                                        ERR_ENTRY_APPLY_MODS_TARGETS_RDN.get(entry.getDN());
                                if (!errors.contains(msg)) {
                                    errors.add(msg);
                                }

                                if (resultCode == null) {
                                    resultCode = ResultCode.NOT_ALLOWED_ON_RDN;
                                }
                                break deleteValueLoop;
                            }

                            final boolean removed = e.removeAttributeValue(name, values[i]);
                            if (!(lenient || removed)) {
                                if (resultCode == null) {
                                    resultCode = ResultCode.NO_SUCH_ATTRIBUTE;
                                }
                                errors.add(ERR_ENTRY_APPLY_MODS_DELETE_NONEXISTENT_VALUE.get(
                                        m.getValues()[i], name));
                            }
                        }
                    }
                    break;

                case ModificationType.REPLACE_INT_VALUE:
                    if ((rdn != null) && rdn.hasAttribute(name)) {
                        final String msg =
                                ERR_ENTRY_APPLY_MODS_TARGETS_RDN.get(entry.getDN());
                        if (!errors.contains(msg)) {
                            errors.add(msg);
                        }

                        if (resultCode == null) {
                            resultCode = ResultCode.NOT_ALLOWED_ON_RDN;
                        }
                        continue;
                    }

                    if (values.length == 0) {
                        e.removeAttribute(name);
                    } else {
                        e.setAttribute(m.getAttribute());
                    }
                    break;

                case ModificationType.INCREMENT_INT_VALUE:
                    final Attribute a = e.getAttribute(name);
                    if ((a == null) || (!a.hasValue())) {
                        errors.add(ERR_ENTRY_APPLY_MODS_INCREMENT_NO_SUCH_ATTR.get(name));
                        continue;
                    }

                    if (a.size() > 1) {
                        errors.add(ERR_ENTRY_APPLY_MODS_INCREMENT_NOT_SINGLE_VALUED.get(
                                name));
                        continue;
                    }

                    if ((rdn != null) && rdn.hasAttribute(name)) {
                        final String msg =
                                ERR_ENTRY_APPLY_MODS_TARGETS_RDN.get(entry.getDN());
                        if (!errors.contains(msg)) {
                            errors.add(msg);
                        }

                        if (resultCode == null) {
                            resultCode = ResultCode.NOT_ALLOWED_ON_RDN;
                        }
                        continue;
                    }

                    final BigInteger currentValue;
                    try {
                        currentValue = new BigInteger(a.getValue());
                    } catch (NumberFormatException nfe) {
                        debugException(nfe);
                        errors.add(
                                ERR_ENTRY_APPLY_MODS_INCREMENT_ENTRY_VALUE_NOT_INTEGER.get(
                                        name, a.getValue()));
                        continue;
                    }

                    if (values.length == 0) {
                        errors.add(ERR_ENTRY_APPLY_MODS_INCREMENT_NO_MOD_VALUES.get(name));
                        continue;
                    } else if (values.length > 1) {
                        errors.add(ERR_ENTRY_APPLY_MODS_INCREMENT_MULTIPLE_MOD_VALUES.get(
                                name));
                        continue;
                    }

                    final BigInteger incrementValue;
                    final String incrementValueStr = m.getValues()[0];
                    try {
                        incrementValue = new BigInteger(incrementValueStr);
                    } catch (NumberFormatException nfe) {
                        debugException(nfe);
                        errors.add(ERR_ENTRY_APPLY_MODS_INCREMENT_MOD_VALUE_NOT_INTEGER.get(
                                name, incrementValueStr));
                        continue;
                    }

                    final BigInteger newValue = currentValue.add(incrementValue);
                    e.setAttribute(name, newValue.toString());
                    break;

                default:
                    errors.add(ERR_ENTRY_APPLY_MODS_UNKNOWN_TYPE.get(
                            String.valueOf(m.getModificationType())));
                    break;
            }
        }

        if (errors.isEmpty()) {
            return e;
        }

        if (resultCode == null) {
            resultCode = ResultCode.CONSTRAINT_VIOLATION;
        }

        throw new LDAPException(resultCode,
                ERR_ENTRY_APPLY_MODS_FAILURE.get(e.getDN(),
                        concatenateStrings(errors)));
    }



    @Override()
    public int hashCode() {
        int hashCode = 0;
        try {
            hashCode += getParsedDN().hashCode();
        } catch (LDAPException le) {
            debugException(le);
            hashCode += dn.hashCode();
        }

        for (final Attribute a : attributes.values()) {
            hashCode += a.hashCode();
        }

        return hashCode;
    }



    @Override()
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        }

        if (o == this) {
            return true;
        }

        if (!(o instanceof Entry)) {
            return false;
        }

        final Entry e = (Entry) o;

        try {
            final DN thisDN = getParsedDN();
            final DN thatDN = e.getParsedDN();
            if (!thisDN.equals(thatDN)) {
                return false;
            }
        } catch (LDAPException le) {
            debugException(le);
            if (!dn.equals(e.dn)) {
                return false;
            }
        }

        if (attributes.size() != e.attributes.size()) {
            return false;
        }

        for (final Attribute a : attributes.values()) {
            if (!e.hasAttribute(a)) {
                return false;
            }
        }

        return true;
    }



    public Entry duplicate() {
        return new Entry(dn, schema, attributes.values());
    }



    public final String[] toLDIF() {
        return toLDIF(0);
    }



    public final String[] toLDIF(final int wrapColumn) {
        List<String> ldifLines = new ArrayList<String>(2 * attributes.size());
        ldifLines.add(LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(dn)));

        for (final Attribute a : attributes.values()) {
            final String name = a.getName();
            for (final ASN1OctetString value : a.getRawValues()) {
                ldifLines.add(LDIFWriter.encodeNameAndValue(name, value));
            }
        }

        if (wrapColumn > 2) {
            ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
        }

        final String[] lineArray = new String[ldifLines.size()];
        ldifLines.toArray(lineArray);
        return lineArray;
    }



    public final void toLDIF(final ByteStringBuffer buffer) {
        toLDIF(buffer, 0);
    }



    public final void toLDIF(final ByteStringBuffer buffer, final int wrapColumn) {
        LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(dn), buffer,
                wrapColumn);
        buffer.append(EOL_BYTES);

        for (final Attribute a : attributes.values()) {
            final String name = a.getName();
            for (final ASN1OctetString value : a.getRawValues()) {
                LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
                buffer.append(EOL_BYTES);
            }
        }
    }


    public final String toLDIFString() {
        final StringBuilder buffer = new StringBuilder();
        toLDIFString(buffer, 0);
        return buffer.toString();
    }



    public final String toLDIFString(final int wrapColumn) {
        final StringBuilder buffer = new StringBuilder();
        toLDIFString(buffer, wrapColumn);
        return buffer.toString();
    }


    public final void toLDIFString(final StringBuilder buffer) {
        toLDIFString(buffer, 0);
    }



    public final void toLDIFString(final StringBuilder buffer,
                                   final int wrapColumn) {
        LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(dn), buffer,
                wrapColumn);
        buffer.append(EOL);

        for (final Attribute a : attributes.values()) {
            final String name = a.getName();
            for (final ASN1OctetString value : a.getRawValues()) {
                LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
                buffer.append(EOL);
            }
        }
    }



    @Override()
    public final String toString() {
        final StringBuilder buffer = new StringBuilder();
        toString(buffer);
        return buffer.toString();
    }

    public void toString(final StringBuilder buffer) {
        buffer.append("Entry(dn='");
        buffer.append(dn);
        buffer.append("', attributes={");

        final Iterator<Attribute> iterator = attributes.values().iterator();

        while (iterator.hasNext()) {
            iterator.next().toString(buffer);
            if (iterator.hasNext()) {
                buffer.append(", ");
            }
        }

        buffer.append("})");
    }
}
