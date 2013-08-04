package com.hwlcn.ldap.ldap.sdk.persist;


import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.*;
import com.hwlcn.ldap.ldap.sdk.schema.ObjectClassDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.ObjectClassType;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import java.io.Serializable;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.debugException;
import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPObjectHandler<T>
        implements Serializable {

    private static final long serialVersionUID = -1480360011153517161L;

    private final Attribute objectClassAttribute;

    private final Class<T> type;

    private final Constructor<T> constructor;

    private final DN defaultParentDN;

    private final Field dnField;

    private final Field entryField;

    private final LDAPObject ldapObject;

    private final LDAPObjectHandler<? super T> superclassHandler;

    private final List<FieldInfo> alwaysAllowedFilterFields;

    private final List<FieldInfo> conditionallyAllowedFilterFields;

    private final List<FieldInfo> requiredFilterFields;

    private final List<FieldInfo> rdnFields;

    private final List<GetterInfo> alwaysAllowedFilterGetters;

    private final List<GetterInfo> conditionallyAllowedFilterGetters;

    private final List<GetterInfo> requiredFilterGetters;

    private final List<GetterInfo> rdnGetters;

    private final Map<String, FieldInfo> fieldMap;

    private final Map<String, GetterInfo> getterMap;

    private final Map<String, SetterInfo> setterMap;

    private final Method postDecodeMethod;

    private final Method postEncodeMethod;

    private final String structuralClass;

    private final String[] attributesToRequest;

    private final String[] auxiliaryClasses;

    private final String[] lazilyLoadedAttributes;

    private final String[] superiorClasses;


    @SuppressWarnings("unchecked")
    LDAPObjectHandler(final Class<T> type)
            throws LDAPPersistException {
        this.type = type;

        final Class<? super T> superclassType = type.getSuperclass();
        if (superclassType == null) {
            superclassHandler = null;
        } else {
            final LDAPObject superclassAnnotation =
                    superclassType.getAnnotation(LDAPObject.class);
            if (superclassAnnotation == null) {
                superclassHandler = null;
            } else {
                superclassHandler = new LDAPObjectHandler(superclassType);
            }
        }

        final TreeMap<String, FieldInfo> fields = new TreeMap<String, FieldInfo>();
        final TreeMap<String, GetterInfo> getters = new TreeMap<String, GetterInfo>();
        final TreeMap<String, SetterInfo> setters = new TreeMap<String, SetterInfo>();

        ldapObject = type.getAnnotation(LDAPObject.class);
        if (ldapObject == null) {
            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_OBJECT_NOT_ANNOTATED.get(type.getName()));
        }

        final LinkedHashMap<String, String> objectClasses =
                new LinkedHashMap<String, String>(10);

        final String oc = ldapObject.structuralClass();
        if (oc.length() == 0) {
            structuralClass = getUnqualifiedClassName(type);
        } else {
            structuralClass = oc;
        }

        final StringBuilder invalidReason = new StringBuilder();
        if (PersistUtils.isValidLDAPName(structuralClass, invalidReason)) {
            objectClasses.put(toLowerCase(structuralClass), structuralClass);
        } else {
            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_INVALID_STRUCTURAL_CLASS.get(type.getName(),
                            structuralClass, invalidReason.toString()));
        }

        auxiliaryClasses = ldapObject.auxiliaryClass();
        for (final String auxiliaryClass : auxiliaryClasses) {
            if (PersistUtils.isValidLDAPName(auxiliaryClass, invalidReason)) {
                objectClasses.put(toLowerCase(auxiliaryClass), auxiliaryClass);
            } else {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_INVALID_AUXILIARY_CLASS.get(type.getName(),
                                auxiliaryClass, invalidReason.toString()));
            }
        }

        superiorClasses = ldapObject.superiorClass();
        for (final String superiorClass : superiorClasses) {
            if (PersistUtils.isValidLDAPName(superiorClass, invalidReason)) {
                objectClasses.put(toLowerCase(superiorClass), superiorClass);
            } else {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_INVALID_SUPERIOR_CLASS.get(type.getName(),
                                superiorClass, invalidReason.toString()));
            }
        }

        if (superclassHandler != null) {
            for (final String s : superclassHandler.objectClassAttribute.getValues()) {
                objectClasses.put(toLowerCase(s), s);
            }
        }

        objectClassAttribute = new Attribute("objectClass", objectClasses.values());


        final String parentDNStr = ldapObject.defaultParentDN();
        try {
            defaultParentDN = new DN(parentDNStr);
        } catch (LDAPException le) {
            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_INVALID_DEFAULT_PARENT.get(type.getName(),
                            parentDNStr, le.getMessage()), le);
        }


        final String postDecodeMethodName = ldapObject.postDecodeMethod();
        if (postDecodeMethodName.length() > 0) {
            try {
                postDecodeMethod = type.getDeclaredMethod(postDecodeMethodName);
                postDecodeMethod.setAccessible(true);
            } catch (Exception e) {
                debugException(e);
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_INVALID_POST_DECODE_METHOD.get(type.getName(),
                                postDecodeMethodName, getExceptionMessage(e)), e);
            }
        } else {
            postDecodeMethod = null;
        }


        final String postEncodeMethodName = ldapObject.postEncodeMethod();
        if (postEncodeMethodName.length() > 0) {
            try {
                postEncodeMethod = type.getDeclaredMethod(postEncodeMethodName,
                        Entry.class);
                postEncodeMethod.setAccessible(true);
            } catch (Exception e) {
                debugException(e);
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_INVALID_POST_ENCODE_METHOD.get(type.getName(),
                                postEncodeMethodName, getExceptionMessage(e)), e);
            }
        } else {
            postEncodeMethod = null;
        }


        try {
            constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
        } catch (Exception e) {
            debugException(e);
            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_NO_DEFAULT_CONSTRUCTOR.get(type.getName()), e);
        }

        Field tmpDNField = null;
        Field tmpEntryField = null;
        final LinkedList<FieldInfo> tmpRFilterFields = new LinkedList<FieldInfo>();
        final LinkedList<FieldInfo> tmpAAFilterFields = new LinkedList<FieldInfo>();
        final LinkedList<FieldInfo> tmpCAFilterFields = new LinkedList<FieldInfo>();
        final LinkedList<FieldInfo> tmpRDNFields = new LinkedList<FieldInfo>();
        for (final Field f : type.getDeclaredFields()) {
            final LDAPField fieldAnnotation = f.getAnnotation(LDAPField.class);
            final LDAPDNField dnFieldAnnotation = f.getAnnotation(LDAPDNField.class);
            final LDAPEntryField entryFieldAnnotation =
                    f.getAnnotation(LDAPEntryField.class);

            if (fieldAnnotation != null) {
                f.setAccessible(true);

                final FieldInfo fieldInfo = new FieldInfo(f, type);
                final String attrName = toLowerCase(fieldInfo.getAttributeName());
                if (fields.containsKey(attrName)) {
                    throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
                            type.getName(), fieldInfo.getAttributeName()));
                } else {
                    fields.put(attrName, fieldInfo);
                }

                switch (fieldInfo.getFilterUsage()) {
                    case REQUIRED:
                        tmpRFilterFields.add(fieldInfo);
                        break;
                    case ALWAYS_ALLOWED:
                        tmpAAFilterFields.add(fieldInfo);
                        break;
                    case CONDITIONALLY_ALLOWED:
                        tmpCAFilterFields.add(fieldInfo);
                        break;
                    case EXCLUDED:
                    default:
                        break;
                }

                if (fieldInfo.includeInRDN()) {
                    tmpRDNFields.add(fieldInfo);
                }
            }

            if (dnFieldAnnotation != null) {
                f.setAccessible(true);

                if (fieldAnnotation != null) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_CONFLICTING_FIELD_ANNOTATIONS.get(
                                    type.getName(), "LDAPField", "LDAPDNField", f.getName()));
                }

                if (tmpDNField != null) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_MULTIPLE_DN_FIELDS.get(type.getName()));
                }

                final int modifiers = f.getModifiers();
                if (Modifier.isFinal(modifiers)) {
                    throw new LDAPPersistException(ERR_OBJECT_HANDLER_DN_FIELD_FINAL.get(
                            f.getName(), type.getName()));
                } else if (Modifier.isStatic(modifiers)) {
                    throw new LDAPPersistException(ERR_OBJECT_HANDLER_DN_FIELD_STATIC.get(
                            f.getName(), type.getName()));
                }

                final Class<?> fieldType = f.getType();
                if (fieldType.equals(String.class)) {
                    tmpDNField = f;
                } else {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_INVALID_DN_FIELD_TYPE.get(type.getName(),
                                    f.getName(), fieldType.getName()));
                }
            }

            if (entryFieldAnnotation != null) {
                f.setAccessible(true);

                if (fieldAnnotation != null) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_CONFLICTING_FIELD_ANNOTATIONS.get(
                                    type.getName(), "LDAPField", "LDAPEntryField",
                                    f.getName()));
                }

                if (tmpEntryField != null) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_MULTIPLE_ENTRY_FIELDS.get(type.getName()));
                }

                final int modifiers = f.getModifiers();
                if (Modifier.isFinal(modifiers)) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_ENTRY_FIELD_FINAL.get(f.getName(),
                                    type.getName()));
                } else if (Modifier.isStatic(modifiers)) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_ENTRY_FIELD_STATIC.get(f.getName(),
                                    type.getName()));
                }

                final Class<?> fieldType = f.getType();
                if (fieldType.equals(ReadOnlyEntry.class)) {
                    tmpEntryField = f;
                } else {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_INVALID_ENTRY_FIELD_TYPE.get(type.getName(),
                                    f.getName(), fieldType.getName()));
                }
            }
        }

        dnField = tmpDNField;
        entryField = tmpEntryField;
        requiredFilterFields = Collections.unmodifiableList(tmpRFilterFields);
        alwaysAllowedFilterFields = Collections.unmodifiableList(tmpAAFilterFields);
        conditionallyAllowedFilterFields =
                Collections.unmodifiableList(tmpCAFilterFields);
        rdnFields = Collections.unmodifiableList(tmpRDNFields);

        final LinkedList<GetterInfo> tmpRFilterGetters =
                new LinkedList<GetterInfo>();
        final LinkedList<GetterInfo> tmpAAFilterGetters =
                new LinkedList<GetterInfo>();
        final LinkedList<GetterInfo> tmpCAFilterGetters =
                new LinkedList<GetterInfo>();
        final LinkedList<GetterInfo> tmpRDNGetters = new LinkedList<GetterInfo>();
        for (final Method m : type.getDeclaredMethods()) {
            final LDAPGetter getter = m.getAnnotation(LDAPGetter.class);
            final LDAPSetter setter = m.getAnnotation(LDAPSetter.class);

            if (getter != null) {
                m.setAccessible(true);

                if (setter != null) {
                    throw new LDAPPersistException(
                            ERR_OBJECT_HANDLER_CONFLICTING_METHOD_ANNOTATIONS.get(
                                    type.getName(), "LDAPGetter", "LDAPSetter",
                                    m.getName()));
                }

                final GetterInfo methodInfo = new GetterInfo(m, type);
                final String attrName = toLowerCase(methodInfo.getAttributeName());
                if (fields.containsKey(attrName) || getters.containsKey(attrName)) {
                    throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
                            type.getName(), methodInfo.getAttributeName()));
                } else {
                    getters.put(attrName, methodInfo);
                }

                switch (methodInfo.getFilterUsage()) {
                    case REQUIRED:
                        tmpRFilterGetters.add(methodInfo);
                        break;
                    case ALWAYS_ALLOWED:
                        tmpAAFilterGetters.add(methodInfo);
                        break;
                    case CONDITIONALLY_ALLOWED:
                        tmpCAFilterGetters.add(methodInfo);
                        break;
                    case EXCLUDED:
                    default:
                        // No action required.
                        break;
                }

                if (methodInfo.includeInRDN()) {
                    tmpRDNGetters.add(methodInfo);
                }
            }

            if (setter != null) {
                m.setAccessible(true);

                final SetterInfo methodInfo = new SetterInfo(m, type);
                final String attrName = toLowerCase(methodInfo.getAttributeName());
                if (fields.containsKey(attrName) || setters.containsKey(attrName)) {
                    throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
                            type.getName(), methodInfo.getAttributeName()));
                } else {
                    setters.put(attrName, methodInfo);
                }
            }
        }

        requiredFilterGetters = Collections.unmodifiableList(tmpRFilterGetters);
        alwaysAllowedFilterGetters =
                Collections.unmodifiableList(tmpAAFilterGetters);
        conditionallyAllowedFilterGetters =
                Collections.unmodifiableList(tmpCAFilterGetters);

        rdnGetters = Collections.unmodifiableList(tmpRDNGetters);
        if (rdnFields.isEmpty() && rdnGetters.isEmpty()) {
            throw new LDAPPersistException(ERR_OBJECT_HANDLER_NO_RDN_DEFINED.get(
                    type.getName()));
        }

        fieldMap = Collections.unmodifiableMap(fields);
        getterMap = Collections.unmodifiableMap(getters);
        setterMap = Collections.unmodifiableMap(setters);


        final TreeSet<String> attrSet = new TreeSet<String>();
        final TreeSet<String> lazySet = new TreeSet<String>();
        if (ldapObject.requestAllAttributes()) {
            attrSet.add("*");
            attrSet.add("+");
        } else {
            for (final FieldInfo i : fields.values()) {
                if (i.lazilyLoad()) {
                    lazySet.add(i.getAttributeName());
                } else {
                    attrSet.add(i.getAttributeName());
                }
            }

            for (final SetterInfo i : setters.values()) {
                attrSet.add(i.getAttributeName());
            }
        }
        attributesToRequest = new String[attrSet.size()];
        attrSet.toArray(attributesToRequest);

        lazilyLoadedAttributes = new String[lazySet.size()];
        lazySet.toArray(lazilyLoadedAttributes);
    }



    private static <T> LDAPObjectHandler<T> getHandler(final Class<T> type)
            throws LDAPPersistException {
        return new LDAPObjectHandler<T>(type);
    }



    public Class<T> getType() {
        return type;
    }



    public LDAPObjectHandler<?> getSuperclassHandler() {
        return superclassHandler;
    }



    public LDAPObject getLDAPObjectAnnotation() {
        return ldapObject;
    }



    public Constructor<T> getConstructor() {
        return constructor;
    }


    public Field getDNField() {
        return dnField;
    }


    public Field getEntryField() {
        return entryField;
    }


    public DN getDefaultParentDN() {
        return defaultParentDN;
    }


    public String getStructuralClass() {
        return structuralClass;
    }


    public String[] getAuxiliaryClasses() {
        return auxiliaryClasses;
    }



    public String[] getSuperiorClasses() {
        return superiorClasses;
    }


    public String[] getAttributesToRequest() {
        return attributesToRequest;
    }


    public String[] getLazilyLoadedAttributes() {
        return lazilyLoadedAttributes;
    }


    public String getEntryDN(final T o)
            throws LDAPPersistException {
        if (dnField != null) {
            try {
                final Object dnObject = dnField.get(o);
                if (dnObject != null) {
                    return String.valueOf(dnObject);
                }
            } catch (Exception e) {
                debugException(e);
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_ERROR_ACCESSING_DN_FIELD.get(dnField.getName(),
                                type.getName(), getExceptionMessage(e)), e);
            }
        }

        final ReadOnlyEntry entry = getEntry(o);
        if (entry != null) {
            return entry.getDN();
        }

        return null;
    }


    public ReadOnlyEntry getEntry(final T o)
            throws LDAPPersistException {
        if (entryField != null) {
            try {
                final Object entryObject = entryField.get(o);
                if (entryObject != null) {
                    return (ReadOnlyEntry) entryObject;
                }
            } catch (Exception e) {
                debugException(e);
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_ERROR_ACCESSING_ENTRY_FIELD.get(
                                entryField.getName(), type.getName(), getExceptionMessage(e)),
                        e);
            }
        }

        return null;
    }


    public Map<String, FieldInfo> getFields() {
        return fieldMap;
    }


    public Map<String, GetterInfo> getGetters() {
        return getterMap;
    }


    public Map<String, SetterInfo> getSetters() {
        return setterMap;
    }


    List<ObjectClassDefinition> constructObjectClasses(final OIDAllocator a)
            throws LDAPPersistException {
        final LinkedHashMap<String, ObjectClassDefinition> ocMap =
                new LinkedHashMap<String, ObjectClassDefinition>(
                        1 + auxiliaryClasses.length);

        if (superclassHandler != null) {
            for (final ObjectClassDefinition d :
                    superclassHandler.constructObjectClasses(a)) {
                ocMap.put(toLowerCase(d.getNameOrOID()), d);
            }
        }

        final String lowerStructuralClass = toLowerCase(structuralClass);
        if (!ocMap.containsKey(lowerStructuralClass)) {
            if (superclassHandler == null) {
                ocMap.put(lowerStructuralClass, constructObjectClass(structuralClass,
                        "top", ObjectClassType.STRUCTURAL, a));
            } else {
                ocMap.put(lowerStructuralClass, constructObjectClass(structuralClass,
                        superclassHandler.getStructuralClass(), ObjectClassType.STRUCTURAL,
                        a));
            }
        }

        for (final String s : auxiliaryClasses) {
            final String lowerName = toLowerCase(s);
            if (!ocMap.containsKey(lowerName)) {
                ocMap.put(lowerName,
                        constructObjectClass(s, "top", ObjectClassType.AUXILIARY, a));
            }
        }

        return Collections.unmodifiableList(new ArrayList<ObjectClassDefinition>(
                ocMap.values()));
    }


    ObjectClassDefinition constructObjectClass(final String name,
                                               final String sup,
                                               final ObjectClassType type,
                                               final OIDAllocator a) {
        final TreeMap<String, String> requiredAttrs = new TreeMap<String, String>();
        final TreeMap<String, String> optionalAttrs = new TreeMap<String, String>();

        for (final FieldInfo i : fieldMap.values()) {
            boolean found = false;
            for (final String s : i.getObjectClasses()) {
                if (name.equalsIgnoreCase(s)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                continue;
            }

            final String attrName = i.getAttributeName();
            final String lowerName = toLowerCase(attrName);
            if (i.includeInRDN() ||
                    (i.isRequiredForDecode() && i.isRequiredForEncode())) {
                requiredAttrs.put(lowerName, attrName);
            } else {
                optionalAttrs.put(lowerName, attrName);
            }
        }

        for (final GetterInfo i : getterMap.values()) {
            boolean found = false;
            for (final String s : i.getObjectClasses()) {
                if (name.equalsIgnoreCase(s)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                continue;
            }

            final String attrName = i.getAttributeName();
            final String lowerName = toLowerCase(attrName);
            if (i.includeInRDN()) {
                requiredAttrs.put(lowerName, attrName);
            } else {
                optionalAttrs.put(lowerName, attrName);
            }
        }

        if (name.equalsIgnoreCase(structuralClass)) {
            for (final SetterInfo i : setterMap.values()) {
                final String attrName = i.getAttributeName();
                final String lowerName = toLowerCase(attrName);
                if (requiredAttrs.containsKey(lowerName) ||
                        optionalAttrs.containsKey(lowerName)) {
                    continue;
                }

                optionalAttrs.put(lowerName, attrName);
            }
        }

        final String[] reqArray = new String[requiredAttrs.size()];
        requiredAttrs.values().toArray(reqArray);

        final String[] optArray = new String[optionalAttrs.size()];
        optionalAttrs.values().toArray(optArray);

        return new ObjectClassDefinition(a.allocateObjectClassOID(name),
                new String[]{name}, null, false, new String[]{sup}, type,
                reqArray, optArray, null);
    }



    T decode(final Entry e)
            throws LDAPPersistException {
        final T o;
        try {
            o = constructor.newInstance();
        } catch (Throwable t) {
            debugException(t);

            if (t instanceof InvocationTargetException) {
                t = ((InvocationTargetException) t).getTargetException();
            }

            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_ERROR_INVOKING_CONSTRUCTOR.get(type.getName(),
                            getExceptionMessage(t)), t);
        }

        decode(o, e);
        return o;
    }



    void decode(final T o, final Entry e)
            throws LDAPPersistException {
        if (superclassHandler != null) {
            superclassHandler.decode(o, e);
        }

        setDNAndEntryFields(o, e);

        final ArrayList<String> failureReasons = new ArrayList<String>(5);
        boolean successful = true;

        for (final FieldInfo i : fieldMap.values()) {
            successful &= i.decode(o, e, failureReasons);
        }

        for (final SetterInfo i : setterMap.values()) {
            successful &= i.invokeSetter(o, e, failureReasons);
        }

        Throwable cause = null;
        if (postDecodeMethod != null) {
            try {
                postDecodeMethod.invoke(o);
            } catch (final Throwable t) {
                debugException(t);

                if (t instanceof InvocationTargetException) {
                    cause = ((InvocationTargetException) t).getTargetException();
                } else {
                    cause = t;
                }

                successful = false;
                failureReasons.add(
                        ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_DECODE_METHOD.get(
                                postDecodeMethod.getName(), type.getName(),
                                getExceptionMessage(t)));
            }
        }

        if (!successful) {
            throw new LDAPPersistException(concatenateStrings(failureReasons), o,
                    cause);
        }
    }


    Entry encode(final T o, final String parentDN)
            throws LDAPPersistException {
        // Get the attributes that should be included in the entry.
        final LinkedHashMap<String, Attribute> attrMap =
                new LinkedHashMap<String, Attribute>();
        attrMap.put("objectClass", objectClassAttribute);

        for (final Map.Entry<String, FieldInfo> e : fieldMap.entrySet()) {
            final FieldInfo i = e.getValue();
            if (!i.includeInAdd()) {
                continue;
            }

            final Attribute a = i.encode(o, false);
            if (a != null) {
                attrMap.put(e.getKey(), a);
            }
        }

        for (final Map.Entry<String, GetterInfo> e : getterMap.entrySet()) {
            final GetterInfo i = e.getValue();
            if (!i.includeInAdd()) {
                continue;
            }

            final Attribute a = i.encode(o);
            if (a != null) {
                attrMap.put(e.getKey(), a);
            }
        }

        final String dn = constructDN(o, parentDN, attrMap);
        final Entry entry = new Entry(dn, attrMap.values());

        if (postEncodeMethod != null) {
            try {
                postEncodeMethod.invoke(o, entry);
            } catch (Throwable t) {
                debugException(t);

                if (t instanceof InvocationTargetException) {
                    t = ((InvocationTargetException) t).getTargetException();
                }

                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_ENCODE_METHOD.get(
                                postEncodeMethod.getName(), type.getName(),
                                getExceptionMessage(t)), t);
            }
        }

        setDNAndEntryFields(o, entry);

        if (superclassHandler != null) {
            final Entry e = superclassHandler.encode(o, parentDN);
            for (final Attribute a : e.getAttributes()) {
                entry.addAttribute(a);
            }
        }

        return entry;
    }

    private void setDNAndEntryFields(final T o, final Entry e)
            throws LDAPPersistException {
        if (dnField != null) {
            try {
                dnField.set(o, e.getDN());
            } catch (Exception ex) {
                debugException(ex);
                throw new LDAPPersistException(ERR_OBJECT_HANDLER_ERROR_SETTING_DN.get(
                        type.getName(), e.getDN(), dnField.getName(),
                        getExceptionMessage(ex)), ex);
            }
        }

        if (entryField != null) {
            try {
                entryField.set(o, new ReadOnlyEntry(e));
            } catch (Exception ex) {
                debugException(ex);
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_ERROR_SETTING_ENTRY.get(type.getName(),
                                entryField.getName(), getExceptionMessage(ex)), ex);
            }
        }
    }


    public String constructDN(final T o, final String parentDN)
            throws LDAPPersistException {
        final String existingDN = getEntryDN(o);
        if (existingDN != null) {
            return existingDN;
        }

        final LinkedHashMap<String, Attribute> attrMap =
                new LinkedHashMap<String, Attribute>(1);

        for (final FieldInfo i : rdnFields) {
            final Attribute a = i.encode(o, true);
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_RDN_FIELD_MISSING_VALUE.get(type.getName(),
                                i.getField().getName()));
            }

            attrMap.put(toLowerCase(i.getAttributeName()), a);
        }

        for (final GetterInfo i : rdnGetters) {
            final Attribute a = i.encode(o);
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_RDN_GETTER_MISSING_VALUE.get(type.getName(),
                                i.getMethod().getName()));
            }

            attrMap.put(toLowerCase(i.getAttributeName()), a);
        }

        return constructDN(o, parentDN, attrMap);
    }


    String constructDN(final T o, final String parentDN,
                       final Map<String, Attribute> attrMap)
            throws LDAPPersistException {
        final String existingDN = getEntryDN(o);
        if (existingDN != null) {
            return existingDN;
        }

        final ArrayList<String> rdnNameList = new ArrayList<String>(1);
        final ArrayList<byte[]> rdnValueList = new ArrayList<byte[]>(1);
        for (final FieldInfo i : rdnFields) {
            final Attribute a = attrMap.get(toLowerCase(i.getAttributeName()));
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_RDN_FIELD_MISSING_VALUE.get(type.getName(),
                                i.getField().getName()));
            }

            rdnNameList.add(a.getName());
            rdnValueList.add(a.getValueByteArray());
        }

        for (final GetterInfo i : rdnGetters) {
            final Attribute a = attrMap.get(toLowerCase(i.getAttributeName()));
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_RDN_GETTER_MISSING_VALUE.get(type.getName(),
                                i.getMethod().getName()));
            }

            rdnNameList.add(a.getName());
            rdnValueList.add(a.getValueByteArray());
        }

        final String[] rdnNames = new String[rdnNameList.size()];
        rdnNameList.toArray(rdnNames);

        final byte[][] rdnValues = new byte[rdnNames.length][];
        rdnValueList.toArray(rdnValues);

        final RDN rdn = new RDN(rdnNames, rdnValues);

        if (parentDN == null) {
            return new DN(rdn, defaultParentDN).toString();
        } else {
            try {
                final DN parsedParentDN = new DN(parentDN);
                return new DN(rdn, parsedParentDN).toString();
            } catch (LDAPException le) {
                debugException(le);
                throw new LDAPPersistException(ERR_OBJECT_HANDLER_INVALID_PARENT_DN.get(
                        type.getName(), parentDN, le.getMessage()), le);
            }
        }
    }


    List<Modification> getModifications(final T o, final boolean deleteNullValues,
                                        final String... attributes)
            throws LDAPPersistException {
        final ReadOnlyEntry originalEntry;
        if (entryField != null) {
            originalEntry = getEntry(o);
        } else {
            originalEntry = null;
        }
        if (originalEntry != null) {
            try {
                final T decodedOrig = decode(originalEntry);
                final Entry reEncodedOriginal =
                        encode(decodedOrig, originalEntry.getParentDNString());

                final Entry newEntry = encode(o, originalEntry.getParentDNString());
                final List<Modification> mods = Entry.diff(reEncodedOriginal, newEntry,
                        true, false, attributes);
                if (!deleteNullValues) {
                    final Iterator<Modification> iterator = mods.iterator();
                    while (iterator.hasNext()) {
                        final Modification m = iterator.next();
                        if (m.getRawValues().length == 0) {
                            iterator.remove();
                        }
                    }
                }

                HashSet<String> stripAttrs = null;
                for (final FieldInfo i : fieldMap.values()) {
                    if (!i.includeInModify()) {
                        if (stripAttrs == null) {
                            stripAttrs = new HashSet<String>(10);
                        }
                        stripAttrs.add(toLowerCase(i.getAttributeName()));
                    }
                }

                for (final GetterInfo i : getterMap.values()) {
                    if (!i.includeInModify()) {
                        if (stripAttrs == null) {
                            stripAttrs = new HashSet<String>(10);
                        }
                        stripAttrs.add(toLowerCase(i.getAttributeName()));
                    }
                }

                if (stripAttrs != null) {
                    final Iterator<Modification> iterator = mods.iterator();
                    while (iterator.hasNext()) {
                        final Modification m = iterator.next();
                        if (stripAttrs.contains(toLowerCase(m.getAttributeName()))) {
                            iterator.remove();
                        }
                    }
                }

                return mods;
            } catch (final Exception e) {
                debugException(e);
            } finally {
                setDNAndEntryFields(o, originalEntry);
            }
        }

        final HashSet<String> attrSet;
        if ((attributes == null) || (attributes.length == 0)) {
            attrSet = null;
        } else {
            attrSet = new HashSet<String>(attributes.length);
            for (final String s : attributes) {
                attrSet.add(toLowerCase(s));
            }
        }

        final ArrayList<Modification> mods = new ArrayList<Modification>(5);

        for (final Map.Entry<String, FieldInfo> e : fieldMap.entrySet()) {
            final String attrName = toLowerCase(e.getKey());
            if ((attrSet != null) && (!attrSet.contains(attrName))) {
                continue;
            }

            final FieldInfo i = e.getValue();
            if (!i.includeInModify()) {
                continue;
            }

            final Attribute a = i.encode(o, false);
            if (a == null) {
                if (!deleteNullValues) {
                    continue;
                }

                if ((originalEntry != null) && (!originalEntry.hasAttribute(attrName))) {
                    continue;
                }

                mods.add(new Modification(ModificationType.REPLACE,
                        i.getAttributeName()));
                continue;
            }

            if (originalEntry != null) {
                final Attribute originalAttr = originalEntry.getAttribute(attrName);
                if ((originalAttr != null) && originalAttr.equals(a)) {
                    continue;
                }
            }

            mods.add(new Modification(ModificationType.REPLACE, i.getAttributeName(),
                    a.getRawValues()));
        }

        for (final Map.Entry<String, GetterInfo> e : getterMap.entrySet()) {
            final String attrName = toLowerCase(e.getKey());
            if ((attrSet != null) && (!attrSet.contains(attrName))) {
                continue;
            }

            final GetterInfo i = e.getValue();
            if (!i.includeInModify()) {
                continue;
            }

            final Attribute a = i.encode(o);
            if (a == null) {
                if (!deleteNullValues) {
                    continue;
                }

                if ((originalEntry != null) && (!originalEntry.hasAttribute(attrName))) {
                    continue;
                }

                mods.add(new Modification(ModificationType.REPLACE,
                        i.getAttributeName()));
                continue;
            }

            if (originalEntry != null) {
                final Attribute originalAttr = originalEntry.getAttribute(attrName);
                if ((originalAttr != null) && originalAttr.equals(a)) {
                    continue;
                }
            }

            mods.add(new Modification(ModificationType.REPLACE, i.getAttributeName(),
                    a.getRawValues()));
        }

        if (superclassHandler != null) {
            final List<Modification> superMods =
                    superclassHandler.getModifications(o, deleteNullValues, attributes);
            final ArrayList<Modification> modsToAdd =
                    new ArrayList<Modification>(superMods.size());
            for (final Modification sm : superMods) {
                boolean add = true;
                for (final Modification m : mods) {
                    if (m.getAttributeName().equalsIgnoreCase(sm.getAttributeName())) {
                        add = false;
                        break;
                    }
                }
                if (add) {
                    modsToAdd.add(sm);
                }
            }
            mods.addAll(modsToAdd);
        }

        return Collections.unmodifiableList(mods);
    }


    public Filter createBaseFilter() {
        if (auxiliaryClasses.length == 0) {
            return Filter.createEqualityFilter("objectClass", structuralClass);
        } else {
            final ArrayList<Filter> comps =
                    new ArrayList<Filter>(1 + auxiliaryClasses.length);
            comps.add(Filter.createEqualityFilter("objectClass", structuralClass));
            for (final String s : auxiliaryClasses) {
                comps.add(Filter.createEqualityFilter("objectClass", s));
            }
            return Filter.createANDFilter(comps);
        }
    }


    public Filter createFilter(final T o)
            throws LDAPPersistException {
        final AtomicBoolean addedRequiredOrAllowed = new AtomicBoolean(false);

        final Filter f = createFilter(o, addedRequiredOrAllowed);
        if (!addedRequiredOrAllowed.get()) {
            throw new LDAPPersistException(
                    ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_OR_ALLOWED.get());
        }

        return f;
    }


    private Filter createFilter(final T o,
                                final AtomicBoolean addedRequiredOrAllowed)
            throws LDAPPersistException {
        final ArrayList<Attribute> attrs = new ArrayList<Attribute>(5);
        attrs.add(objectClassAttribute);

        for (final FieldInfo i : requiredFilterFields) {
            final Attribute a = i.encode(o, true);
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_FIELD.get(
                                i.getField().getName()));
            } else {
                attrs.add(a);
                addedRequiredOrAllowed.set(true);
            }
        }

        for (final GetterInfo i : requiredFilterGetters) {
            final Attribute a = i.encode(o);
            if (a == null) {
                throw new LDAPPersistException(
                        ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_GETTER.get(
                                i.getMethod().getName()));
            } else {
                attrs.add(a);
                addedRequiredOrAllowed.set(true);
            }
        }

        for (final FieldInfo i : alwaysAllowedFilterFields) {
            final Attribute a = i.encode(o, true);
            if (a != null) {
                attrs.add(a);
                addedRequiredOrAllowed.set(true);
            }
        }

        for (final GetterInfo i : alwaysAllowedFilterGetters) {
            final Attribute a = i.encode(o);
            if (a != null) {
                attrs.add(a);
                addedRequiredOrAllowed.set(true);
            }
        }

        for (final FieldInfo i : conditionallyAllowedFilterFields) {
            final Attribute a = i.encode(o, true);
            if (a != null) {
                attrs.add(a);
            }
        }

        for (final GetterInfo i : conditionallyAllowedFilterGetters) {
            final Attribute a = i.encode(o);
            if (a != null) {
                attrs.add(a);
            }
        }

        final ArrayList<Filter> comps = new ArrayList<Filter>(attrs.size());
        for (final Attribute a : attrs) {
            for (final ASN1OctetString v : a.getRawValues()) {
                comps.add(Filter.createEqualityFilter(a.getName(), v.getValue()));
            }
        }

        if (superclassHandler != null) {
            final Filter f =
                    superclassHandler.createFilter(o, addedRequiredOrAllowed);
            if (f.getFilterType() == Filter.FILTER_TYPE_AND) {
                comps.addAll(Arrays.asList(f.getComponents()));
            } else {
                comps.add(f);
            }
        }

        return Filter.createANDFilter(comps);
    }
}
