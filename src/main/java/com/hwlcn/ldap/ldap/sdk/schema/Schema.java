package com.hwlcn.ldap.ldap.sdk.schema;



import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ReadOnlyEntry;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.ldap.ldif.LDIFReader;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.schema.SchemaMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Schema
       implements Serializable
{

  public static final String ATTR_ATTRIBUTE_SYNTAX = "ldapSyntaxes";

  public static final String ATTR_ATTRIBUTE_TYPE = "attributeTypes";

  public static final String ATTR_DIT_CONTENT_RULE = "dITContentRules";

  public static final String ATTR_DIT_STRUCTURE_RULE = "dITStructureRules";

  public static final String ATTR_MATCHING_RULE = "matchingRules";

  public static final String ATTR_MATCHING_RULE_USE = "matchingRuleUse";

  public static final String ATTR_NAME_FORM = "nameForms";

  public static final String ATTR_OBJECT_CLASS = "objectClasses";


  public static final String ATTR_SUBSCHEMA_SUBENTRY = "subschemaSubentry";

  private static final AtomicReference<Schema> DEFAULT_STANDARD_SCHEMA =
       new AtomicReference<Schema>();

  private static final String[] SCHEMA_REQUEST_ATTRS =
  {
    ATTR_ATTRIBUTE_SYNTAX,
    ATTR_ATTRIBUTE_TYPE,
    ATTR_DIT_CONTENT_RULE,
    ATTR_DIT_STRUCTURE_RULE,
    ATTR_MATCHING_RULE,
    ATTR_MATCHING_RULE_USE,
    ATTR_NAME_FORM,
    ATTR_OBJECT_CLASS
  };


  private static final String[] SUBSCHEMA_SUBENTRY_REQUEST_ATTRS =
  {
    ATTR_SUBSCHEMA_SUBENTRY
  };

  private static final String DEFAULT_SCHEMA_RESOURCE_PATH =
          "com/hwlcn/ldap/ldap/sdk/schema/standard-schema.ldif";

  private static final long serialVersionUID = 8081839633831517925L;

  private final Map<AttributeTypeDefinition,List<AttributeTypeDefinition>>
       subordinateAttributeTypes;

  private final Map<String,AttributeSyntaxDefinition> asMap;

  private final Map<String,AttributeTypeDefinition> atMap;

  private final Map<String,DITContentRuleDefinition> dcrMap;

  private final Map<Integer,DITStructureRuleDefinition> dsrMapByID;

  private final Map<String,DITStructureRuleDefinition> dsrMapByName;

  private final Map<String,DITStructureRuleDefinition> dsrMapByNameForm;

  private final Map<String,MatchingRuleDefinition> mrMap;

  private final Map<String,MatchingRuleUseDefinition> mruMap;

  private final Map<String,NameFormDefinition> nfMapByName;

  private final Map<String,NameFormDefinition> nfMapByOC;

  private final Map<String,ObjectClassDefinition> ocMap;

  private final ReadOnlyEntry schemaEntry;

  private final Set<AttributeSyntaxDefinition> asSet;

  private final Set<AttributeTypeDefinition> atSet;

  private final Set<AttributeTypeDefinition> operationalATSet;

  private final Set<AttributeTypeDefinition> userATSet;

  private final Set<DITContentRuleDefinition> dcrSet;

  private final Set<DITStructureRuleDefinition> dsrSet;

  private final Set<MatchingRuleDefinition> mrSet;

  private final Set<MatchingRuleUseDefinition> mruSet;

  private final Set<NameFormDefinition> nfSet;

  private final Set<ObjectClassDefinition> ocSet;

  private final Set<ObjectClassDefinition> abstractOCSet;

  private final Set<ObjectClassDefinition> auxiliaryOCSet;

  private final Set<ObjectClassDefinition> structuralOCSet;


  public Schema(final Entry schemaEntry)
  {
    this.schemaEntry = new ReadOnlyEntry(schemaEntry);

    String[] defs = schemaEntry.getAttributeValues(ATTR_ATTRIBUTE_SYNTAX);
    if (defs == null)
    {
      asMap = Collections.emptyMap();
      asSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,AttributeSyntaxDefinition> m =
           new LinkedHashMap<String,AttributeSyntaxDefinition>(defs.length);
      final LinkedHashSet<AttributeSyntaxDefinition> s =
           new LinkedHashSet<AttributeSyntaxDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final AttributeSyntaxDefinition as =
               new AttributeSyntaxDefinition(def);
          s.add(as);
          m.put(toLowerCase(as.getOID()), as);
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      asMap = Collections.unmodifiableMap(m);
      asSet = Collections.unmodifiableSet(s);
    }


    defs = schemaEntry.getAttributeValues(ATTR_ATTRIBUTE_TYPE);
    if (defs == null)
    {
      atMap            = Collections.emptyMap();
      atSet            = Collections.emptySet();
      operationalATSet = Collections.emptySet();
      userATSet        = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,AttributeTypeDefinition> m =
           new LinkedHashMap<String,AttributeTypeDefinition>(2*defs.length);
      final LinkedHashSet<AttributeTypeDefinition> s =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);
      final LinkedHashSet<AttributeTypeDefinition> sUser =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);
      final LinkedHashSet<AttributeTypeDefinition> sOperational =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final AttributeTypeDefinition at = new AttributeTypeDefinition(def);
          s.add(at);
          m.put(toLowerCase(at.getOID()), at);
          for (final String name : at.getNames())
          {
            m.put(toLowerCase(name), at);
          }

          if (at.isOperational())
          {
            sOperational.add(at);
          }
          else
          {
            sUser.add(at);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      atMap            = Collections.unmodifiableMap(m);
      atSet            = Collections.unmodifiableSet(s);
      operationalATSet = Collections.unmodifiableSet(sOperational);
      userATSet        = Collections.unmodifiableSet(sUser);
    }


    defs = schemaEntry.getAttributeValues(ATTR_DIT_CONTENT_RULE);
    if (defs == null)
    {
      dcrMap = Collections.emptyMap();
      dcrSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,DITContentRuleDefinition> m =
           new LinkedHashMap<String,DITContentRuleDefinition>(2*defs.length);
      final LinkedHashSet<DITContentRuleDefinition> s =
           new LinkedHashSet<DITContentRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final DITContentRuleDefinition dcr =
               new DITContentRuleDefinition(def);
          s.add(dcr);
          m.put(toLowerCase(dcr.getOID()), dcr);
          for (final String name : dcr.getNames())
          {
            m.put(toLowerCase(name), dcr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      dcrMap = Collections.unmodifiableMap(m);
      dcrSet = Collections.unmodifiableSet(s);
    }

    defs = schemaEntry.getAttributeValues(ATTR_DIT_STRUCTURE_RULE);
    if (defs == null)
    {
      dsrMapByID       = Collections.emptyMap();
      dsrMapByName     = Collections.emptyMap();
      dsrMapByNameForm = Collections.emptyMap();
      dsrSet           = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<Integer,DITStructureRuleDefinition> mID =
           new LinkedHashMap<Integer,DITStructureRuleDefinition>(defs.length);
      final LinkedHashMap<String,DITStructureRuleDefinition> mN =
           new LinkedHashMap<String,DITStructureRuleDefinition>(defs.length);
      final LinkedHashMap<String,DITStructureRuleDefinition> mNF =
           new LinkedHashMap<String,DITStructureRuleDefinition>(defs.length);
      final LinkedHashSet<DITStructureRuleDefinition> s =
           new LinkedHashSet<DITStructureRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final DITStructureRuleDefinition dsr =
               new DITStructureRuleDefinition(def);
          s.add(dsr);
          mID.put(dsr.getRuleID(), dsr);
          mNF.put(toLowerCase(dsr.getNameFormID()), dsr);
          for (final String name : dsr.getNames())
          {
            mN.put(toLowerCase(name), dsr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      dsrMapByID       = Collections.unmodifiableMap(mID);
      dsrMapByName     = Collections.unmodifiableMap(mN);
      dsrMapByNameForm = Collections.unmodifiableMap(mNF);
      dsrSet           = Collections.unmodifiableSet(s);
    }


    defs = schemaEntry.getAttributeValues(ATTR_MATCHING_RULE);
    if (defs == null)
    {
      mrMap = Collections.emptyMap();
      mrSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,MatchingRuleDefinition> m =
           new LinkedHashMap<String,MatchingRuleDefinition>(2*defs.length);
      final LinkedHashSet<MatchingRuleDefinition> s =
           new LinkedHashSet<MatchingRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final MatchingRuleDefinition mr = new MatchingRuleDefinition(def);
          s.add(mr);
          m.put(toLowerCase(mr.getOID()), mr);
          for (final String name : mr.getNames())
          {
            m.put(toLowerCase(name), mr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      mrMap = Collections.unmodifiableMap(m);
      mrSet = Collections.unmodifiableSet(s);
    }

    defs = schemaEntry.getAttributeValues(ATTR_MATCHING_RULE_USE);
    if (defs == null)
    {
      mruMap = Collections.emptyMap();
      mruSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,MatchingRuleUseDefinition> m =
           new LinkedHashMap<String,MatchingRuleUseDefinition>(2*defs.length);
      final LinkedHashSet<MatchingRuleUseDefinition> s =
           new LinkedHashSet<MatchingRuleUseDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final MatchingRuleUseDefinition mru =
               new MatchingRuleUseDefinition(def);
          s.add(mru);
          m.put(toLowerCase(mru.getOID()), mru);
          for (final String name : mru.getNames())
          {
            m.put(toLowerCase(name), mru);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      mruMap = Collections.unmodifiableMap(m);
      mruSet = Collections.unmodifiableSet(s);
    }

    defs = schemaEntry.getAttributeValues(ATTR_NAME_FORM);
    if (defs == null)
    {
      nfMapByName = Collections.emptyMap();
      nfMapByOC   = Collections.emptyMap();
      nfSet       = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,NameFormDefinition> mN =
           new LinkedHashMap<String,NameFormDefinition>(2*defs.length);
      final LinkedHashMap<String,NameFormDefinition> mOC =
           new LinkedHashMap<String,NameFormDefinition>(defs.length);
      final LinkedHashSet<NameFormDefinition> s =
           new LinkedHashSet<NameFormDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final NameFormDefinition nf = new NameFormDefinition(def);
          s.add(nf);
          mOC.put(toLowerCase(nf.getStructuralClass()), nf);
          mN.put(toLowerCase(nf.getOID()), nf);
          for (final String name : nf.getNames())
          {
            mN.put(toLowerCase(name), nf);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      nfMapByName = Collections.unmodifiableMap(mN);
      nfMapByOC   = Collections.unmodifiableMap(mOC);
      nfSet       = Collections.unmodifiableSet(s);
    }


    defs = schemaEntry.getAttributeValues(ATTR_OBJECT_CLASS);
    if (defs == null)
    {
      ocMap           = Collections.emptyMap();
      ocSet           = Collections.emptySet();
      abstractOCSet   = Collections.emptySet();
      auxiliaryOCSet  = Collections.emptySet();
      structuralOCSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,ObjectClassDefinition> m =
           new LinkedHashMap<String,ObjectClassDefinition>(2*defs.length);
      final LinkedHashSet<ObjectClassDefinition> s =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sAbstract =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sAuxiliary =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sStructural =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final ObjectClassDefinition oc = new ObjectClassDefinition(def);
          s.add(oc);
          m.put(toLowerCase(oc.getOID()), oc);
          for (final String name : oc.getNames())
          {
            m.put(toLowerCase(name), oc);
          }

          switch (getOCType(oc, m))
          {
            case ABSTRACT:
              sAbstract.add(oc);
              break;
            case AUXILIARY:
              sAuxiliary.add(oc);
              break;
            case STRUCTURAL:
              sStructural.add(oc);
              break;
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      ocMap           = Collections.unmodifiableMap(m);
      ocSet           = Collections.unmodifiableSet(s);
      abstractOCSet   = Collections.unmodifiableSet(sAbstract);
      auxiliaryOCSet  = Collections.unmodifiableSet(sAuxiliary);
      structuralOCSet = Collections.unmodifiableSet(sStructural);
    }


    final LinkedHashMap<AttributeTypeDefinition,List<AttributeTypeDefinition>>
         subAttrTypes = new LinkedHashMap<AttributeTypeDefinition,
              List<AttributeTypeDefinition>>(atSet.size());
    for (final AttributeTypeDefinition d : atSet)
    {
      AttributeTypeDefinition sup = d.getSuperiorType(this);
      while (sup != null)
      {
        List<AttributeTypeDefinition> l = subAttrTypes.get(sup);
        if (l == null)
        {
          l = new ArrayList<AttributeTypeDefinition>(1);
          subAttrTypes.put(sup, l);
        }
        l.add(d);

        sup = sup.getSuperiorType(this);
      }
    }
    subordinateAttributeTypes = Collections.unmodifiableMap(subAttrTypes);
  }

  public static Schema getSchema(final LDAPConnection connection)
         throws LDAPException
  {
    return getSchema(connection, "");
  }



  public static Schema getSchema(final LDAPConnection connection,
                                 final String entryDN)
         throws LDAPException
  {
    ensureNotNull(connection);

    final String subschemaSubentryDN;
    if (entryDN == null)
    {
      subschemaSubentryDN = getSubschemaSubentryDN(connection, "");
    }
    else
    {
      subschemaSubentryDN = getSubschemaSubentryDN(connection, entryDN);
    }

    if (subschemaSubentryDN == null)
    {
      return null;
    }

    final Entry schemaEntry =
         connection.getEntry(subschemaSubentryDN, SCHEMA_REQUEST_ATTRS);
    if (schemaEntry == null)
    {
      return null;
    }

    return new Schema(schemaEntry);
  }



  public static Schema getSchema(final String... schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.length == 0);

    final ArrayList<File> files = new ArrayList<File>(schemaFiles.length);
    for (final String s : schemaFiles)
    {
      files.add(new File(s));
    }

    return getSchema(files);
  }




  public static Schema getSchema(final File... schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.length == 0);

    return getSchema(Arrays.asList(schemaFiles));
  }


  public static Schema getSchema(final List<File> schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.isEmpty());

    Entry schemaEntry = null;
    for (final File f : schemaFiles)
    {
      final LDIFReader ldifReader = new LDIFReader(f);

      try
      {
        final Entry e = ldifReader.readEntry();
        if (e == null)
        {
          continue;
        }

        if (schemaEntry == null)
        {
          schemaEntry = e;
        }
        else
        {
          for (final Attribute a : e.getAttributes())
          {
            schemaEntry.addAttribute(a);
          }
        }
      }
      finally
      {
        ldifReader.close();
      }
    }

    if (schemaEntry == null)
    {
      return null;
    }

    return new Schema(schemaEntry);
  }



  public static Schema getDefaultStandardSchema()
         throws LDAPException
  {
    synchronized (DEFAULT_STANDARD_SCHEMA)
    {
      final Schema s = DEFAULT_STANDARD_SCHEMA.get();
      if (s != null)
      {
        return s;
      }

      try
      {
        final ClassLoader classLoader = Schema.class.getClassLoader();
        final InputStream inputStream =
             classLoader.getResourceAsStream(DEFAULT_SCHEMA_RESOURCE_PATH);
        final LDIFReader ldifReader = new LDIFReader(inputStream);
        final Entry schemaEntry = ldifReader.readEntry();
        ldifReader.close();

        final Schema schema = new Schema(schemaEntry);
        DEFAULT_STANDARD_SCHEMA.set(schema);
        return schema;
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SCHEMA_CANNOT_LOAD_DEFAULT_DEFINITIONS.get(
                  getExceptionMessage(e)),
             e);
      }
    }
  }



  public static Schema mergeSchemas(final Schema... schemas)
  {
    if ((schemas == null) || (schemas.length == 0))
    {
      return null;
    }
    else if (schemas.length == 1)
    {
      return schemas[0];
    }

    final LinkedHashMap<String,String> asMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> atMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> dcrMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<Integer,String> dsrMap =
         new LinkedHashMap<Integer,String>();
    final LinkedHashMap<String,String> mrMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> mruMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> nfMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> ocMap =
         new LinkedHashMap<String,String>();

    for (final Schema s : schemas)
    {
      for (final AttributeSyntaxDefinition as : s.asSet)
      {
        asMap.put(toLowerCase(as.getOID()), as.toString());
      }

      for (final AttributeTypeDefinition at : s.atSet)
      {
        atMap.put(toLowerCase(at.getOID()), at.toString());
      }

      for (final DITContentRuleDefinition dcr : s.dcrSet)
      {
        dcrMap.put(toLowerCase(dcr.getOID()), dcr.toString());
      }

      for (final DITStructureRuleDefinition dsr : s.dsrSet)
      {
        dsrMap.put(dsr.getRuleID(), dsr.toString());
      }

      for (final MatchingRuleDefinition mr : s.mrSet)
      {
        mrMap.put(toLowerCase(mr.getOID()), mr.toString());
      }

      for (final MatchingRuleUseDefinition mru : s.mruSet)
      {
        mruMap.put(toLowerCase(mru.getOID()), mru.toString());
      }

      for (final NameFormDefinition nf : s.nfSet)
      {
        nfMap.put(toLowerCase(nf.getOID()), nf.toString());
      }

      for (final ObjectClassDefinition oc : s.ocSet)
      {
        ocMap.put(toLowerCase(oc.getOID()), oc.toString());
      }
    }

    final Entry e = new Entry(schemas[0].getSchemaEntry().getDN());

    final Attribute ocAttr =
         schemas[0].getSchemaEntry().getObjectClassAttribute();
    if (ocAttr == null)
    {
      e.addAttribute("objectClass", "top", "ldapSubEntry", "subschema");
    }
    else
    {
      e.addAttribute(ocAttr);
    }

    if (! asMap.isEmpty())
    {
      final String[] values = new String[asMap.size()];
      e.addAttribute(ATTR_ATTRIBUTE_SYNTAX, asMap.values().toArray(values));
    }

    if (! mrMap.isEmpty())
    {
      final String[] values = new String[mrMap.size()];
      e.addAttribute(ATTR_MATCHING_RULE, mrMap.values().toArray(values));
    }

    if (! atMap.isEmpty())
    {
      final String[] values = new String[atMap.size()];
      e.addAttribute(ATTR_ATTRIBUTE_TYPE, atMap.values().toArray(values));
    }

    if (! ocMap.isEmpty())
    {
      final String[] values = new String[ocMap.size()];
      e.addAttribute(ATTR_OBJECT_CLASS, ocMap.values().toArray(values));
    }

    if (! dcrMap.isEmpty())
    {
      final String[] values = new String[dcrMap.size()];
      e.addAttribute(ATTR_DIT_CONTENT_RULE, dcrMap.values().toArray(values));
    }

    if (! dsrMap.isEmpty())
    {
      final String[] values = new String[dsrMap.size()];
      e.addAttribute(ATTR_DIT_STRUCTURE_RULE, dsrMap.values().toArray(values));
    }

    if (! nfMap.isEmpty())
    {
      final String[] values = new String[nfMap.size()];
      e.addAttribute(ATTR_NAME_FORM, nfMap.values().toArray(values));
    }

    if (! mruMap.isEmpty())
    {
      final String[] values = new String[mruMap.size()];
      e.addAttribute(ATTR_MATCHING_RULE_USE, mruMap.values().toArray(values));
    }

    return new Schema(e);
  }


  public ReadOnlyEntry getSchemaEntry()
  {
    return schemaEntry;
  }

  private static ObjectClassType getOCType(final ObjectClassDefinition oc,
                                      final Map<String,ObjectClassDefinition> m)
  {
    ObjectClassType t = oc.getObjectClassType();
    if (t != null)
    {
      return t;
    }

    for (final String s : oc.getSuperiorClasses())
    {
      final ObjectClassDefinition d = m.get(toLowerCase(s));
      if (d != null)
      {
        t = getOCType(d, m);
        if (t != null)
        {
          return t;
        }
      }
    }

    return ObjectClassType.STRUCTURAL;
  }

  public static String getSubschemaSubentryDN(final LDAPConnection connection,
                                              final String entryDN)
         throws LDAPException
  {
    ensureNotNull(connection);

    final Entry e;
    if (entryDN == null)
    {
      e = connection.getEntry("", SUBSCHEMA_SUBENTRY_REQUEST_ATTRS);
    }
    else
    {
      e = connection.getEntry(entryDN, SUBSCHEMA_SUBENTRY_REQUEST_ATTRS);
    }

    if (e == null)
    {
      return null;
    }

    return e.getAttributeValue(ATTR_SUBSCHEMA_SUBENTRY);
  }


  public Set<AttributeSyntaxDefinition> getAttributeSyntaxes()
  {
    return asSet;
  }

  public AttributeSyntaxDefinition getAttributeSyntax(final String oid)
  {
    ensureNotNull(oid);

    final String lowerOID = toLowerCase(oid);
    final int    curlyPos = lowerOID.indexOf('{');

    if (curlyPos > 0)
    {
      return asMap.get(lowerOID.substring(0, curlyPos));
    }
    else
    {
      return asMap.get(lowerOID);
    }
  }

  public Set<AttributeTypeDefinition> getAttributeTypes()
  {
    return atSet;
  }

  public Set<AttributeTypeDefinition> getOperationalAttributeTypes()
  {
    return operationalATSet;
  }

  public Set<AttributeTypeDefinition> getUserAttributeTypes()
  {
    return userATSet;
  }

  public AttributeTypeDefinition getAttributeType(final String name)
  {
    ensureNotNull(name);

    return atMap.get(toLowerCase(name));
  }

  public List<AttributeTypeDefinition> getSubordinateAttributeTypes(
                                            final AttributeTypeDefinition d)
  {
    ensureNotNull(d);

    final List<AttributeTypeDefinition> l = subordinateAttributeTypes.get(d);
    if (l == null)
    {
      return Collections.emptyList();
    }
    else
    {
      return Collections.unmodifiableList(l);
    }
  }

  public Set<DITContentRuleDefinition> getDITContentRules()
  {
    return dcrSet;
  }

  public DITContentRuleDefinition getDITContentRule(final String name)
  {
    ensureNotNull(name);

    return dcrMap.get(toLowerCase(name));
  }

  public Set<DITStructureRuleDefinition> getDITStructureRules()
  {
    return dsrSet;
  }


  public DITStructureRuleDefinition getDITStructureRuleByID(final int ruleID)
  {
    return dsrMapByID.get(ruleID);
  }

  public DITStructureRuleDefinition getDITStructureRuleByName(
                                         final String ruleName)
  {
    ensureNotNull(ruleName);

    return dsrMapByName.get(toLowerCase(ruleName));
  }


  public DITStructureRuleDefinition getDITStructureRuleByNameForm(
                                         final String nameForm)
  {
    ensureNotNull(nameForm);

    return dsrMapByNameForm.get(toLowerCase(nameForm));
  }

  public Set<MatchingRuleDefinition> getMatchingRules()
  {
    return mrSet;
  }


  public MatchingRuleDefinition getMatchingRule(final String name)
  {
    ensureNotNull(name);

    return mrMap.get(toLowerCase(name));
  }


  public Set<MatchingRuleUseDefinition> getMatchingRuleUses()
  {
    return mruSet;
  }



  public MatchingRuleUseDefinition getMatchingRuleUse(final String name)
  {
    ensureNotNull(name);

    return mruMap.get(toLowerCase(name));
  }


  public Set<NameFormDefinition> getNameForms()
  {
    return nfSet;
  }


  public NameFormDefinition getNameFormByName(final String name)
  {
    ensureNotNull(name);

    return nfMapByName.get(toLowerCase(name));
  }


  public NameFormDefinition getNameFormByObjectClass(final String objectClass)
  {
    ensureNotNull(objectClass);

    return nfMapByOC.get(toLowerCase(objectClass));
  }


  public Set<ObjectClassDefinition> getObjectClasses()
  {
    return ocSet;
  }


  public Set<ObjectClassDefinition> getAbstractObjectClasses()
  {
    return abstractOCSet;
  }

  public Set<ObjectClassDefinition> getAuxiliaryObjectClasses()
  {
    return auxiliaryOCSet;
  }


  public Set<ObjectClassDefinition> getStructuralObjectClasses()
  {
    return structuralOCSet;
  }


  public ObjectClassDefinition getObjectClass(final String name)
  {
    ensureNotNull(name);

    return ocMap.get(toLowerCase(name));
  }

  @Override()
  public int hashCode()
  {
    int hc;
    try
    {
      hc = schemaEntry.getParsedDN().hashCode();
    }
    catch (final Exception e)
    {
      debugException(e);
      hc = toLowerCase(schemaEntry.getDN()).hashCode();
    }

    Attribute a = schemaEntry.getAttribute(ATTR_ATTRIBUTE_SYNTAX);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_MATCHING_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_ATTRIBUTE_TYPE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_OBJECT_CLASS);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_NAME_FORM);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_DIT_CONTENT_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_DIT_STRUCTURE_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_MATCHING_RULE_USE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    return hc;
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

    if (! (o instanceof Schema))
    {
      return false;
    }

    final Schema s = (Schema) o;

    try
    {
      if (! schemaEntry.getParsedDN().equals(s.schemaEntry.getParsedDN()))
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      debugException(e);
      if (! schemaEntry.getDN().equalsIgnoreCase(s.schemaEntry.getDN()))
      {
        return false;
      }
    }

    return (asSet.equals(s.asSet) &&
         mrSet.equals(s.mrSet) &&
         atSet.equals(s.atSet) &&
         ocSet.equals(s.ocSet) &&
         nfSet.equals(s.nfSet) &&
         dcrSet.equals(s.dcrSet) &&
         dsrSet.equals(s.dsrSet) &&
         mruSet.equals(s.mruSet));
  }

  @Override()
  public String toString()
  {
    return schemaEntry.toString();
  }
}
