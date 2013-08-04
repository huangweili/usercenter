package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.hwlcn.ldap.ldap.sdk.AddRequest;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.BindResult;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DeleteRequest;
import com.hwlcn.ldap.ldap.sdk.DereferencePolicy;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPEntrySource;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModificationType;
import com.hwlcn.ldap.ldap.sdk.ModifyRequest;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchRequest;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.ldap.ldap.sdk.SearchScope;
import com.hwlcn.ldap.ldap.sdk.SimpleBindRequest;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.ObjectClassDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPPersister<T>
       implements Serializable
{

  private static final long serialVersionUID = -4001743482496453961L;

  private static final Control[] NO_CONTROLS = new Control[0];

  private static final ConcurrentHashMap<Class<?>,LDAPPersister<?>> INSTANCES =
       new ConcurrentHashMap<Class<?>,LDAPPersister<?>>();

  private final LDAPObjectHandler<T> handler;


  private LDAPPersister(final Class<T> type)
          throws LDAPPersistException
  {
    handler = new LDAPObjectHandler<T>(type);
  }

  @SuppressWarnings("unchecked")
  public static <T> LDAPPersister<T> getInstance(final Class<T> type)
         throws LDAPPersistException
  {
    ensureNotNull(type);

    LDAPPersister<T> p = (LDAPPersister<T>) INSTANCES.get(type);
    if (p == null)
    {
      p = new LDAPPersister<T>(type);
      INSTANCES.put(type, p);
    }

    return p;
  }


  public LDAPObject getLDAPObjectAnnotation()
  {
    return handler.getLDAPObjectAnnotation();
  }


  public LDAPObjectHandler<T> getObjectHandler()
  {
    return handler;
  }


  public List<AttributeTypeDefinition> constructAttributeTypes()
         throws LDAPPersistException
  {
    return constructAttributeTypes(DefaultOIDAllocator.getInstance());
  }


  public List<AttributeTypeDefinition> constructAttributeTypes(
                                            final OIDAllocator a)
         throws LDAPPersistException
  {
    final LinkedList<AttributeTypeDefinition> attrList =
         new LinkedList<AttributeTypeDefinition>();

    for (final FieldInfo i : handler.getFields().values())
    {
      attrList.add(i.constructAttributeType(a));
    }

    for (final GetterInfo i : handler.getGetters().values())
    {
      attrList.add(i.constructAttributeType(a));
    }

    return Collections.unmodifiableList(attrList);
  }

  public List<ObjectClassDefinition> constructObjectClasses()
         throws LDAPPersistException
  {
    return constructObjectClasses(DefaultOIDAllocator.getInstance());
  }


  public List<ObjectClassDefinition> constructObjectClasses(
                                          final OIDAllocator a)
         throws LDAPPersistException
  {
    return handler.constructObjectClasses(a);
  }


  public boolean updateSchema(final LDAPInterface i)
         throws LDAPException
  {
    return updateSchema(i, DefaultOIDAllocator.getInstance());
  }


  public boolean updateSchema(final LDAPInterface i, final OIDAllocator a)
         throws LDAPException
  {
    final Schema s = i.getSchema();

    final List<AttributeTypeDefinition> generatedTypes =
         constructAttributeTypes(a);
    final List<ObjectClassDefinition> generatedClasses =
         constructObjectClasses(a);

    final LinkedList<String> newAttrList = new LinkedList<String>();
    for (final AttributeTypeDefinition d : generatedTypes)
    {
      if (s.getAttributeType(d.getNameOrOID()) == null)
      {
        newAttrList.add(d.toString());
      }
    }

    final LinkedList<String> newOCList = new LinkedList<String>();
    for (final ObjectClassDefinition d : generatedClasses)
    {
      final ObjectClassDefinition existing = s.getObjectClass(d.getNameOrOID());
      if (existing == null)
      {
        newOCList.add(d.toString());
      }
      else
      {
        final Set<AttributeTypeDefinition> existingRequired =
             existing.getRequiredAttributes(s, true);
        final Set<AttributeTypeDefinition> existingOptional =
             existing.getOptionalAttributes(s, true);

        final LinkedHashSet<String> newOptionalNames =
             new LinkedHashSet<String>(0);
        addMissingAttrs(d.getRequiredAttributes(), existingRequired,
             existingOptional, newOptionalNames);
        addMissingAttrs(d.getOptionalAttributes(), existingRequired,
             existingOptional, newOptionalNames);

        if (! newOptionalNames.isEmpty())
        {
          final LinkedHashSet<String> newOptionalSet =
               new LinkedHashSet<String>();
          newOptionalSet.addAll(
               Arrays.asList(existing.getOptionalAttributes()));
          newOptionalSet.addAll(newOptionalNames);

          final String[] newOptional = new String[newOptionalSet.size()];
          newOptionalSet.toArray(newOptional);

          final ObjectClassDefinition newOC = new ObjectClassDefinition(
               existing.getOID(), existing.getNames(),
               existing.getDescription(), existing.isObsolete(),
               existing.getSuperiorClasses(), existing.getObjectClassType(),
               existing.getRequiredAttributes(), newOptional,
               existing.getExtensions());
          newOCList.add(newOC.toString());
        }
      }
    }

    final LinkedList<Modification> mods = new LinkedList<Modification>();
    if (! newAttrList.isEmpty())
    {
      final String[] newAttrValues = new String[newAttrList.size()];
      mods.add(new Modification(ModificationType.ADD,
           Schema.ATTR_ATTRIBUTE_TYPE, newAttrList.toArray(newAttrValues)));
    }

    if (! newOCList.isEmpty())
    {
      final String[] newOCValues = new String[newOCList.size()];
      mods.add(new Modification(ModificationType.ADD,
           Schema.ATTR_OBJECT_CLASS, newOCList.toArray(newOCValues)));
    }

    if (mods.isEmpty())
    {
      return false;
    }
    else
    {
      i.modify(s.getSchemaEntry().getDN(), mods);
      return true;
    }
  }


  private static void addMissingAttrs(final String[] names,
                           final Set<AttributeTypeDefinition> required,
                           final Set<AttributeTypeDefinition> optional,
                           final Set<String> missing)
  {
    for (final String name : names)
    {
      boolean found = false;
      for (final AttributeTypeDefinition eA : required)
      {
        if (eA.hasNameOrOID(name))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        for (final AttributeTypeDefinition eA : optional)
        {
          if (eA.hasNameOrOID(name))
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          missing.add(name);
        }
      }
    }
  }

  public Entry encode(final T o, final String parentDN)
         throws LDAPPersistException
  {
    ensureNotNull(o);
    return handler.encode(o, parentDN);
  }


  public T decode(final Entry entry)
         throws LDAPPersistException
  {
    ensureNotNull(entry);
    return handler.decode(entry);
  }



  public void decode(final T o, final Entry entry)
         throws LDAPPersistException
  {
    ensureNotNull(o, entry);
    handler.decode(o, entry);
  }


  public LDAPResult add(final T o, final LDAPInterface i, final String parentDN,
                        final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final Entry e = encode(o, parentDN);

    try
    {
      final AddRequest addRequest = new AddRequest(e);
      if (controls != null)
      {
        addRequest.setControls(controls);
      }

      return i.add(addRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }


  public LDAPResult delete(final T o, final LDAPInterface i,
                           final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final String dn = handler.getEntryDN(o);
    if (dn == null)
    {
      throw new LDAPPersistException(ERR_PERSISTER_DELETE_NO_DN.get());
    }

    try
    {
      final DeleteRequest deleteRequest = new DeleteRequest(dn);
      if (controls != null)
      {
        deleteRequest.setControls(controls);
      }

      return i.delete(deleteRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }


  public List<Modification> getModifications(final T o,
                                             final boolean deleteNullValues,
                                             final String... attributes)
         throws LDAPPersistException
  {
    ensureNotNull(o);
    return handler.getModifications(o, deleteNullValues, attributes);
  }



  public LDAPResult modify(final T o, final LDAPInterface i, final String dn,
                           final boolean deleteNullValues,
                           final String... attributes)
         throws LDAPPersistException
  {
    return modify(o, i, dn, deleteNullValues, attributes, NO_CONTROLS);
  }



  public LDAPResult modify(final T o, final LDAPInterface i, final String dn,
                           final boolean deleteNullValues,
                           final String[] attributes, final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final List<Modification> mods =
         handler.getModifications(o, deleteNullValues, attributes);
    if (mods.isEmpty())
    {
      return null;
    }

    final String targetDN;
    if (dn == null)
    {
      targetDN = handler.getEntryDN(o);
      if (targetDN == null)
      {
        throw new LDAPPersistException(ERR_PERSISTER_MODIFY_NO_DN.get());
      }
    }
    else
    {
      targetDN = dn;
    }

    try
    {
      final ModifyRequest modifyRequest = new ModifyRequest(targetDN, mods);
      if (controls != null)
      {
        modifyRequest.setControls(controls);
      }

      return i.modify(modifyRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }


  public BindResult bind(final T o, final String baseDN, final String password,
                         final LDAPConnection c, final Control... controls)
         throws LDAPException
  {
    ensureNotNull(o, password, c);

    String dn = handler.getEntryDN(o);
    if (dn == null)
    {
      String base = baseDN;
      if (base == null)
      {
        base = handler.getDefaultParentDN().toString();
      }

      final SearchRequest r = new SearchRequest(base, SearchScope.SUB,
           handler.createFilter(o), SearchRequest.NO_ATTRIBUTES);
      r.setSizeLimit(1);

      final Entry e = c.searchForEntry(r);
      if (e == null)
      {
        throw new LDAPException(ResultCode.NO_RESULTS_RETURNED,
             ERR_PERSISTER_BIND_NO_ENTRY_FOUND.get());
      }
      else
      {
        dn = e.getDN();
      }
    }

    return c.bind(new SimpleBindRequest(dn, password, controls));
  }



  public T get(final T o, final LDAPInterface i, final String parentDN)
         throws LDAPPersistException
  {
    final String dn = handler.constructDN(o, parentDN);

    final Entry entry;
    try
    {
      entry = i.getEntry(dn, handler.getAttributesToRequest());
      if (entry == null)
      {
        return null;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return decode(entry);
  }


  public T get(final String dn, final LDAPInterface i)
         throws LDAPPersistException
  {
    final Entry entry;
    try
    {
      entry = i.getEntry(dn, handler.getAttributesToRequest());
      if (entry == null)
      {
        return null;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return decode(entry);
  }



  public void lazilyLoad(final T o, final LDAPInterface i,
                         final FieldInfo... fields)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);

    final String[] attrs;
    if ((fields == null) || (fields.length == 0))
    {
      attrs = handler.getLazilyLoadedAttributes();
    }
    else
    {
      final ArrayList<String> attrList = new ArrayList<String>(fields.length);
      for (final FieldInfo f : fields)
      {
        if (f.lazilyLoad())
        {
          attrList.add(f.getAttributeName());
        }
      }
      attrs = new String[attrList.size()];
      attrList.toArray(attrs);
    }

    if (attrs.length == 0)
    {
      return;
    }

    final String dn = handler.getEntryDN(o);
    if (dn == null)
    {
      throw new LDAPPersistException(ERR_PERSISTER_LAZILY_LOAD_NO_DN.get());
    }

    final Entry entry;
    try
    {
      entry = i.getEntry(handler.getEntryDN(o), attrs);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    if (entry == null)
    {
      throw new LDAPPersistException(
           ERR_PERSISTER_LAZILY_LOAD_NO_ENTRY.get(dn));
    }

    boolean successful = true;
    final ArrayList<String> failureReasons = new ArrayList<String>(5);
    final Map<String,FieldInfo> fieldMap = handler.getFields();
    for (final Attribute a : entry.getAttributes())
    {
      final String lowerName = toLowerCase(a.getName());
      final FieldInfo f = fieldMap.get(lowerName);
      if (f != null)
      {
        successful &= f.decode(o, entry, failureReasons);
      }
    }

    if (! successful)
    {
      throw new LDAPPersistException(concatenateStrings(failureReasons), o,
           null);
    }
  }



  public PersistedObjects<T> search(final T o, final LDAPConnection c)
         throws LDAPPersistException
  {
    return search(o, c, null, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
         null, NO_CONTROLS);
  }



  public PersistedObjects<T> search(final T o, final LDAPConnection c,
                                    final String baseDN,
                                    final SearchScope scope)
         throws LDAPPersistException
  {
    return search(o, c, baseDN, scope, DereferencePolicy.NEVER, 0, 0, null,
         NO_CONTROLS);
  }


  public PersistedObjects<T> search(final T o, final LDAPConnection c,
                                    final String baseDN,
                                    final SearchScope scope,
                                    final DereferencePolicy derefPolicy,
                                    final int sizeLimit, final int timeLimit,
                                    final Filter extraFilter,
                                    final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, c, scope, derefPolicy);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter filter;
    if (extraFilter == null)
    {
      filter = handler.createFilter(o);
    }
    else
    {
      filter = Filter.createANDFilter(handler.createFilter(o), extraFilter);
    }

    final SearchRequest searchRequest = new SearchRequest(base, scope,
         derefPolicy, sizeLimit, timeLimit, false, filter,
         handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    final LDAPEntrySource entrySource;
    try
    {
      entrySource = new LDAPEntrySource(c, searchRequest, false);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return new PersistedObjects<T>(this, entrySource);
  }


  public SearchResult search(final T o, final LDAPInterface i,
                             final ObjectSearchListener<T> l)
         throws LDAPPersistException
  {
    return search(o, i, null, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
         null, l, NO_CONTROLS);
  }


  public SearchResult search(final T o, final LDAPInterface i,
                             final String baseDN, final SearchScope scope,
                             final ObjectSearchListener<T> l)
         throws LDAPPersistException
  {
    return search(o, i, baseDN, scope, DereferencePolicy.NEVER, 0, 0, null, l,
         NO_CONTROLS);
  }




  public SearchResult search(final T o, final LDAPInterface i,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final Filter extraFilter,
                             final ObjectSearchListener<T> l,
                             final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, i, scope, derefPolicy, l);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter filter;
    if (extraFilter == null)
    {
      filter = handler.createFilter(o);
    }
    else
    {
      filter = Filter.createANDFilter(handler.createFilter(o), extraFilter);
    }

    final SearchListenerBridge<T> bridge = new SearchListenerBridge<T>(this, l);

    final SearchRequest searchRequest = new SearchRequest(bridge, base, scope,
         derefPolicy, sizeLimit, timeLimit, false, filter,
         handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    try
    {
      return i.search(searchRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }



  public PersistedObjects<T> search(final LDAPConnection c, final String baseDN,
                                    final SearchScope scope,
                                    final DereferencePolicy derefPolicy,
                                    final int sizeLimit, final int timeLimit,
                                    final Filter filter,
                                    final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(c, scope, derefPolicy, filter);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter f = Filter.createANDFilter(filter, handler.createBaseFilter());

    final SearchRequest searchRequest = new SearchRequest(base, scope,
         derefPolicy, sizeLimit, timeLimit, false, f,
         handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    final LDAPEntrySource entrySource;
    try
    {
      entrySource = new LDAPEntrySource(c, searchRequest, false);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return new PersistedObjects<T>(this, entrySource);
  }


  public SearchResult search(final LDAPInterface i, final String baseDN,
                             final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final Filter filter,
                             final ObjectSearchListener<T> l,
                             final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(i, scope, derefPolicy, filter, l);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter f = Filter.createANDFilter(filter, handler.createBaseFilter());
    final SearchListenerBridge<T> bridge = new SearchListenerBridge<T>(this, l);

    final SearchRequest searchRequest = new SearchRequest(bridge, base, scope,
         derefPolicy, sizeLimit, timeLimit, false, f,
         handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    try
    {
      return i.search(searchRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }


  public T searchForObject(final T o, final LDAPInterface i)
         throws LDAPPersistException
  {
    return searchForObject(o, i, null, SearchScope.SUB, DereferencePolicy.NEVER,
         0, 0, null, NO_CONTROLS);
  }



  public T searchForObject(final T o, final LDAPInterface i,
                           final String baseDN, final SearchScope scope)
         throws LDAPPersistException
  {
    return searchForObject(o, i, baseDN, scope, DereferencePolicy.NEVER, 0, 0,
         null, NO_CONTROLS);
  }



  public T searchForObject(final T o, final LDAPInterface i,
                           final String baseDN, final SearchScope scope,
                           final DereferencePolicy derefPolicy,
                           final int sizeLimit, final int timeLimit,
                           final Filter extraFilter, final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(o, i, scope, derefPolicy);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter filter;
    if (extraFilter == null)
    {
      filter = handler.createFilter(o);
    }
    else
    {
      filter = Filter.createANDFilter(handler.createFilter(o), extraFilter);
    }

    final SearchRequest searchRequest = new SearchRequest(base, scope,
         derefPolicy, sizeLimit, timeLimit, false, filter,
         handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    try
    {
      final Entry e = i.searchForEntry(searchRequest);
      if (e == null)
      {
        return null;
      }
      else
      {
        return decode(e);
      }
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }



  public SearchResult getAll(final LDAPInterface i, final String baseDN,
                             final ObjectSearchListener<T> l,
                             final Control... controls)
         throws LDAPPersistException
  {
    ensureNotNull(i, l);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final SearchListenerBridge<T> bridge = new SearchListenerBridge<T>(this, l);
    final SearchRequest searchRequest = new SearchRequest(bridge, base,
         SearchScope.SUB, DereferencePolicy.NEVER, 0, 0, false,
         handler.createBaseFilter(), handler.getAttributesToRequest());
    if (controls != null)
    {
      searchRequest.setControls(controls);
    }

    try
    {
      return i.search(searchRequest);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }
}
