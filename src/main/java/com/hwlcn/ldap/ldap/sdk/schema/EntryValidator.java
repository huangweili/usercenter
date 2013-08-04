package com.hwlcn.ldap.ldap.sdk.schema;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.RDN;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.schema.SchemaMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class EntryValidator
       implements Serializable
{

  private static final long serialVersionUID = -8945609557086398241L;

  private final AtomicLong entriesExamined;

  private final AtomicLong invalidEntries;

  private final AtomicLong malformedDNs;

  private final AtomicLong missingSuperiorClasses;

  private final AtomicLong multipleStructuralClasses;

  private final AtomicLong nameFormViolations;

  private final AtomicLong noObjectClasses;

  private final AtomicLong noStructuralClass;

  private boolean checkAttributeSyntax;

  private boolean checkMalformedDNs;

  private boolean checkMissingAttributes;

  private boolean checkMissingSuperiorObjectClasses;

  private boolean checkNameForms;

  private boolean checkProhibitedAttributes;

  private boolean checkProhibitedObjectClasses;

  private boolean checkSingleValuedAttributes;

  private boolean checkStructuralObjectClasses;

  private boolean checkUndefinedAttributes;

  private boolean checkUndefinedObjectClasses;

  private final ConcurrentHashMap<String,AtomicLong> attributesViolatingSyntax;

  private final ConcurrentHashMap<String,AtomicLong> missingAttributes;

  private final ConcurrentHashMap<String,AtomicLong> prohibitedAttributes;

  private final ConcurrentHashMap<String,AtomicLong> prohibitedObjectClasses;

  private final ConcurrentHashMap<String,AtomicLong> singleValueViolations;

  private final ConcurrentHashMap<String,AtomicLong> undefinedAttributes;

  private final ConcurrentHashMap<String,AtomicLong> undefinedObjectClasses;

  private final Schema schema;

  public EntryValidator(final Schema schema)
  {
    this.schema = schema;

    checkAttributeSyntax              = true;
    checkMalformedDNs                 = true;
    checkMissingAttributes            = true;
    checkMissingSuperiorObjectClasses = true;
    checkNameForms                    = true;
    checkProhibitedAttributes         = true;
    checkProhibitedObjectClasses      = true;
    checkSingleValuedAttributes       = true;
    checkStructuralObjectClasses      = true;
    checkUndefinedAttributes          = true;
    checkUndefinedObjectClasses       = true;

    entriesExamined           = new AtomicLong(0L);
    invalidEntries            = new AtomicLong(0L);
    malformedDNs              = new AtomicLong(0L);
    missingSuperiorClasses    = new AtomicLong(0L);
    multipleStructuralClasses = new AtomicLong(0L);
    nameFormViolations        = new AtomicLong(0L);
    noObjectClasses           = new AtomicLong(0L);
    noStructuralClass         = new AtomicLong(0L);

    attributesViolatingSyntax = new ConcurrentHashMap<String,AtomicLong>();
    missingAttributes         = new ConcurrentHashMap<String,AtomicLong>();
    prohibitedAttributes      = new ConcurrentHashMap<String,AtomicLong>();
    prohibitedObjectClasses   = new ConcurrentHashMap<String,AtomicLong>();
    singleValueViolations     = new ConcurrentHashMap<String,AtomicLong>();
    undefinedAttributes       = new ConcurrentHashMap<String,AtomicLong>();
    undefinedObjectClasses    = new ConcurrentHashMap<String,AtomicLong>();
  }


  public boolean checkMissingAttributes()
  {
    return checkMissingAttributes;
  }

  public void setCheckMissingAttributes(final boolean checkMissingAttributes)
  {
    this.checkMissingAttributes = checkMissingAttributes;
  }

  public boolean checkMissingSuperiorObjectClasses()
  {
    return checkMissingSuperiorObjectClasses;
  }

  public void setCheckMissingSuperiorObjectClasses(
                   final boolean checkMissingSuperiorObjectClasses)
  {
    this.checkMissingSuperiorObjectClasses = checkMissingSuperiorObjectClasses;
  }

  public boolean checkMalformedDNs()
  {
    return checkMalformedDNs;
  }

  public void setCheckMalformedDNs(final boolean checkMalformedDNs)
  {
    this.checkMalformedDNs = checkMalformedDNs;
  }


  public boolean checkNameForms()
  {
    return checkNameForms;
  }

  public void setCheckNameForms(final boolean checkNameForms)
  {
    this.checkNameForms = checkNameForms;
  }


  public boolean checkProhibitedAttributes()
  {
    return checkProhibitedAttributes;
  }

  public void setCheckProhibitedAttributes(
                   final boolean checkProhibitedAttributes)
  {
    this.checkProhibitedAttributes = checkProhibitedAttributes;
  }


  public boolean checkProhibitedObjectClasses()
  {
    return checkProhibitedObjectClasses;
  }

  public void setCheckProhibitedObjectClasses(
                   final boolean checkProhibitedObjectClasses)
  {
    this.checkProhibitedObjectClasses = checkProhibitedObjectClasses;
  }

  public boolean checkSingleValuedAttributes()
  {
    return checkSingleValuedAttributes;
  }

  public void setCheckSingleValuedAttributes(
                   final boolean checkSingleValuedAttributes)
  {
    this.checkSingleValuedAttributes = checkSingleValuedAttributes;
  }

  public boolean checkStructuralObjectClasses()
  {
    return checkStructuralObjectClasses;
  }

  public void setCheckStructuralObjectClasses(
                   final boolean checkStructuralObjectClasses)
  {
    this.checkStructuralObjectClasses = checkStructuralObjectClasses;
  }

  public boolean checkAttributeSyntax()
  {
    return checkAttributeSyntax;
  }

  public void setCheckAttributeSyntax(final boolean checkAttributeSyntax)
  {
    this.checkAttributeSyntax = checkAttributeSyntax;
  }

  public boolean checkUndefinedAttributes()
  {
    return checkUndefinedAttributes;
  }

  public void setCheckUndefinedAttributes(
                   final boolean checkUndefinedAttributes)
  {
    this.checkUndefinedAttributes = checkUndefinedAttributes;
  }

  public boolean checkUndefinedObjectClasses()
  {
    return checkUndefinedObjectClasses;
  }

  public void setCheckUndefinedObjectClasses(
                   final boolean checkUndefinedObjectClasses)
  {
    this.checkUndefinedObjectClasses = checkUndefinedObjectClasses;
  }


  public boolean entryIsValid(final Entry entry,
                              final List<String> invalidReasons)
  {
    ensureNotNull(entry);

    boolean entryValid = true;
    entriesExamined.incrementAndGet();

    RDN rdn = null;
    try
    {
      rdn = entry.getParsedDN().getRDN();
    }
    catch (LDAPException le)
    {
      debugException(le);
      if (checkMalformedDNs)
      {
        entryValid = false;
        malformedDNs.incrementAndGet();
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_MALFORMED_DN.get(
               getExceptionMessage(le)));
        }
      }
    }

    final HashSet<ObjectClassDefinition> ocSet =
         new HashSet<ObjectClassDefinition>();
    final boolean missingOC =
         (! getObjectClasses(entry, ocSet, invalidReasons));
    if (missingOC)
    {
      entryValid = false;
    }

    DITContentRuleDefinition ditContentRule = null;
    NameFormDefinition nameForm = null;
    if (! missingOC)
    {
      final AtomicReference<ObjectClassDefinition> ref =
           new AtomicReference<ObjectClassDefinition>(null);
      entryValid &= getStructuralClass(ocSet, ref, invalidReasons);
      final ObjectClassDefinition structuralClass = ref.get();
      if (structuralClass != null)
      {
        ditContentRule = schema.getDITContentRule(structuralClass.getOID());
        nameForm =
             schema.getNameFormByObjectClass(structuralClass.getNameOrOID());
      }
    }

    HashSet<AttributeTypeDefinition> requiredAttrs = null;
    if (checkMissingAttributes || checkProhibitedAttributes)
    {
      requiredAttrs = getRequiredAttributes(ocSet, ditContentRule);
      if (checkMissingAttributes)
      {
        entryValid &= checkForMissingAttributes(entry, rdn, requiredAttrs,
                                                invalidReasons);
      }
    }

    HashSet<AttributeTypeDefinition> optionalAttrs = null;
    if (checkProhibitedAttributes)
    {
      optionalAttrs =
           getOptionalAttributes(ocSet, ditContentRule, requiredAttrs);
    }
    for (final Attribute a : entry.getAttributes())
    {
      entryValid &=
           checkAttribute(a, requiredAttrs, optionalAttrs, invalidReasons);
    }

    if (checkProhibitedObjectClasses && (ditContentRule != null))
    {
      entryValid &=
           checkAuxiliaryClasses(ocSet, ditContentRule, invalidReasons);
    }

    if (rdn != null)
    {
      entryValid &= checkRDN(rdn, requiredAttrs, optionalAttrs, nameForm,
                             invalidReasons);
    }

    if (! entryValid)
    {
      invalidEntries.incrementAndGet();
    }

    return entryValid;
  }


  private boolean getObjectClasses(final Entry entry,
                                   final HashSet<ObjectClassDefinition> ocSet,
                                   final List<String> invalidReasons)
  {
    final String[] ocValues = entry.getObjectClassValues();
    if ((ocValues == null) || (ocValues.length == 0))
    {
      noObjectClasses.incrementAndGet();
      if (invalidReasons != null)
      {
        invalidReasons.add(ERR_ENTRY_NO_OCS.get());
      }
      return false;
    }

    boolean entryValid = true;
    final HashSet<String> missingOCs = new HashSet<String>(ocValues.length);
    for (final String ocName : entry.getObjectClassValues())
    {
      final ObjectClassDefinition d = schema.getObjectClass(ocName);
      if (d == null)
      {
        if (checkUndefinedObjectClasses)
        {
          entryValid = false;
          missingOCs.add(toLowerCase(ocName));
          updateCount(ocName, undefinedObjectClasses);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_UNDEFINED_OC.get(ocName));
          }
        }
      }
      else
      {
        ocSet.add(d);
      }
    }

    for (final ObjectClassDefinition d :
         new HashSet<ObjectClassDefinition>(ocSet))
    {
      entryValid &= addSuperiorClasses(d, ocSet, missingOCs, invalidReasons);
    }

    return entryValid;
  }


  private boolean addSuperiorClasses(final ObjectClassDefinition d,
                                     final HashSet<ObjectClassDefinition> ocSet,
                                     final HashSet<String> missingOCNames,
                                     final List<String> invalidReasons)
  {
    boolean entryValid = true;

    for (final String ocName : d.getSuperiorClasses())
    {
      final ObjectClassDefinition supOC = schema.getObjectClass(ocName);
      if (supOC == null)
      {
        if (checkUndefinedObjectClasses)
        {
          entryValid = false;
          final String lowerName = toLowerCase(ocName);
          if (! missingOCNames.contains(lowerName))
          {
            missingOCNames.add(lowerName);
            updateCount(ocName, undefinedObjectClasses);
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_UNDEFINED_SUP_OC.get(
                   d.getNameOrOID(), ocName));
            }
          }
        }
      }
      else
      {
        if (! ocSet.contains(supOC))
        {
          ocSet.add(supOC);
          if (checkMissingSuperiorObjectClasses)
          {
            entryValid = false;
            missingSuperiorClasses.incrementAndGet();
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_MISSING_SUP_OC.get(
                   supOC.getNameOrOID(), d.getNameOrOID()));
            }
          }
        }

        entryValid &=
             addSuperiorClasses(supOC, ocSet, missingOCNames, invalidReasons);
      }
    }

    return entryValid;
  }


  private boolean getStructuralClass(final HashSet<ObjectClassDefinition> ocSet,
               final AtomicReference<ObjectClassDefinition> structuralClass,
               final List<String> invalidReasons)
  {
    final HashSet<ObjectClassDefinition> ocCopy =
         new HashSet<ObjectClassDefinition>(ocSet);
    for (final ObjectClassDefinition d : ocSet)
    {
      final ObjectClassType t = d.getObjectClassType(schema);
      if (t == ObjectClassType.STRUCTURAL)
      {
        ocCopy.removeAll(d.getSuperiorClasses(schema, true));
      }
      else if (t == ObjectClassType.AUXILIARY)
      {
        ocCopy.remove(d);
        ocCopy.removeAll(d.getSuperiorClasses(schema, true));
      }
    }

    boolean entryValid = true;
    Iterator<ObjectClassDefinition> iterator = ocCopy.iterator();
    while (iterator.hasNext())
    {
      final ObjectClassDefinition d = iterator.next();
      if (d.getObjectClassType(schema) == ObjectClassType.ABSTRACT)
      {
        if (checkProhibitedObjectClasses)
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), prohibitedObjectClasses);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_INVALID_ABSTRACT_CLASS.get(
                 d.getNameOrOID()));
          }
        }
        iterator.remove();
      }
    }

    switch (ocCopy.size())
    {
      case 0:
        if (checkStructuralObjectClasses)
        {
          entryValid = false;
          noStructuralClass.incrementAndGet();
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_NO_STRUCTURAL_CLASS.get());
          }
        }
        break;

      case 1:
        structuralClass.set(ocCopy.iterator().next());
        break;

      default:
        if (checkStructuralObjectClasses)
        {
          entryValid = false;
          multipleStructuralClasses.incrementAndGet();
          if (invalidReasons != null)
          {
            final StringBuilder ocList = new StringBuilder();
            iterator = ocCopy.iterator();
            while (iterator.hasNext())
            {
              ocList.append(iterator.next().getNameOrOID());
              if (iterator.hasNext())
              {
                ocList.append(", ");
              }
            }
            invalidReasons.add(
                 ERR_ENTRY_MULTIPLE_STRUCTURAL_CLASSES.get(ocList));
          }
        }
        break;
    }

    return entryValid;
  }

  private HashSet<AttributeTypeDefinition> getRequiredAttributes(
               final HashSet<ObjectClassDefinition> ocSet,
               final DITContentRuleDefinition ditContentRule)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<AttributeTypeDefinition>();
    for (final ObjectClassDefinition oc : ocSet)
    {
      attrSet.addAll(oc.getRequiredAttributes(schema, false));
    }

    if (ditContentRule != null)
    {
      for (final String s : ditContentRule.getRequiredAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          attrSet.add(d);
        }
      }
    }

    return attrSet;
  }

  private HashSet<AttributeTypeDefinition> getOptionalAttributes(
               final HashSet<ObjectClassDefinition> ocSet,
               final DITContentRuleDefinition ditContentRule,
               final HashSet<AttributeTypeDefinition> requiredAttrSet)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<AttributeTypeDefinition>();
    for (final ObjectClassDefinition oc : ocSet)
    {
      if (oc.hasNameOrOID("extensibleObject") ||
          oc.hasNameOrOID("1.3.6.1.4.1.1466.101.120.111"))
      {
        attrSet.addAll(schema.getUserAttributeTypes());
        break;
      }

      for (final AttributeTypeDefinition d :
           oc.getOptionalAttributes(schema, false))
      {
        if (! requiredAttrSet.contains(d))
        {
          attrSet.add(d);
        }
      }
    }

    if (ditContentRule != null)
    {
      for (final String s : ditContentRule.getOptionalAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if ((d != null) && (! requiredAttrSet.contains(d)))
        {
          attrSet.add(d);
        }
      }

      for (final String s : ditContentRule.getProhibitedAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          attrSet.remove(d);
        }
      }
    }

    return attrSet;
  }


  private boolean checkForMissingAttributes(final Entry entry, final RDN rdn,
                       final HashSet<AttributeTypeDefinition> requiredAttrs,
                       final List<String> invalidReasons)
  {
    boolean entryValid = true;

    for (final AttributeTypeDefinition d : requiredAttrs)
    {
      boolean found = false;
      for (final String s : d.getNames())
      {
        if (entry.hasAttribute(s) || ((rdn != null) && rdn.hasAttribute(s)))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        if (! (entry.hasAttribute(d.getOID()) ||
               ((rdn != null) && (rdn.hasAttribute(d.getOID())))))
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), missingAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_MISSING_REQUIRED_ATTR.get(
                 d.getNameOrOID()));
          }
        }
      }
    }

    return entryValid;
  }


  private boolean checkAttribute(final Attribute attr,
                       final HashSet<AttributeTypeDefinition> requiredAttrs,
                       final HashSet<AttributeTypeDefinition> optionalAttrs,
                       final List<String> invalidReasons)
  {
    boolean entryValid = true;

    final AttributeTypeDefinition d =
         schema.getAttributeType(attr.getBaseName());
    if (d == null)
    {
      if (checkUndefinedAttributes)
      {
        entryValid = false;
        updateCount(attr.getBaseName(), undefinedAttributes);
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_UNDEFINED_ATTR.get(attr.getBaseName()));
        }
      }

      return entryValid;
    }

    if (checkProhibitedAttributes && (! d.isOperational()))
    {
      if (! (requiredAttrs.contains(d) || optionalAttrs.contains(d)))
      {
        entryValid = false;
        updateCount(d.getNameOrOID(), prohibitedAttributes);
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_ATTR_NOT_ALLOWED.get(d.getNameOrOID()));
        }
      }
    }

    final ASN1OctetString[] rawValues = attr.getRawValues();
    if (checkSingleValuedAttributes && d.isSingleValued() &&
        (rawValues.length > 1))
    {
      entryValid = false;
      updateCount(d.getNameOrOID(), singleValueViolations);
      if (invalidReasons != null)
      {
        invalidReasons.add(
             ERR_ENTRY_ATTR_HAS_MULTIPLE_VALUES.get(d.getNameOrOID()));
      }
    }

    if (checkAttributeSyntax)
    {
      final MatchingRule r =
           MatchingRule.selectEqualityMatchingRule(d.getNameOrOID(), schema);
      for (final ASN1OctetString v : rawValues)
      {
        try
        {
          r.normalize(v);
        }
        catch (LDAPException le)
        {
          debugException(le);
          entryValid = false;
          updateCount(d.getNameOrOID(), attributesViolatingSyntax);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_ATTR_INVALID_SYNTAX.get(
                 v.stringValue(), d.getNameOrOID(), getExceptionMessage(le)));
          }
        }
      }
    }

    return entryValid;
  }

  private boolean checkAuxiliaryClasses(
                       final HashSet<ObjectClassDefinition> ocSet,
                       final DITContentRuleDefinition ditContentRule,
                       final List<String> invalidReasons)
  {
    final HashSet<ObjectClassDefinition> auxSet =
         new HashSet<ObjectClassDefinition>();
    for (final String s : ditContentRule.getAuxiliaryClasses())
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        auxSet.add(d);
      }
    }

    boolean entryValid = true;
    for (final ObjectClassDefinition d : ocSet)
    {
      final ObjectClassType t = d.getObjectClassType(schema);
      if ((t == ObjectClassType.AUXILIARY) && (! auxSet.contains(d)))
      {
        entryValid = false;
        updateCount(d.getNameOrOID(), prohibitedObjectClasses);
        if (invalidReasons != null)
        {
          invalidReasons.add(
               ERR_ENTRY_AUX_CLASS_NOT_ALLOWED.get(d.getNameOrOID()));
        }
      }
    }

    return entryValid;
  }

  private boolean checkRDN(final RDN rdn,
                           final HashSet<AttributeTypeDefinition> requiredAttrs,
                           final HashSet<AttributeTypeDefinition> optionalAttrs,
                           final NameFormDefinition nameForm,
                           final List<String> invalidReasons)
  {
    final HashSet<AttributeTypeDefinition> nfReqAttrs =
         new HashSet<AttributeTypeDefinition>();
    final HashSet<AttributeTypeDefinition> nfAllowedAttrs =
         new HashSet<AttributeTypeDefinition>();
    if (nameForm != null)
    {
      for (final String s : nameForm.getRequiredAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          nfReqAttrs.add(d);
        }
      }

      nfAllowedAttrs.addAll(nfReqAttrs);
      for (final String s : nameForm.getOptionalAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          nfAllowedAttrs.add(d);
        }
      }
    }

    boolean entryValid = true;
    for (final String s : rdn.getAttributeNames())
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d == null)
      {
        if (checkUndefinedAttributes)
        {
          entryValid = false;
          updateCount(s, undefinedAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_RDN_ATTR_NOT_DEFINED.get(s));
          }
        }
      }
      else
      {
        if (checkProhibitedAttributes &&
            (! (requiredAttrs.contains(d) || optionalAttrs.contains(d) ||
                d.isOperational())))
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), prohibitedAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_RDN_ATTR_NOT_ALLOWED_IN_ENTRY.get(
                 d.getNameOrOID()));
          }
        }

        if (checkNameForms && (nameForm != null))
        {
          if (! nfReqAttrs.remove(d))
          {
            if (! nfAllowedAttrs.contains(d))
            {
              if (entryValid)
              {
                entryValid = false;
                nameFormViolations.incrementAndGet();
              }
              if (invalidReasons != null)
              {
                invalidReasons.add(ERR_ENTRY_RDN_ATTR_NOT_ALLOWED_BY_NF.get(s));
              }
            }
          }
        }
      }
    }

    if (checkNameForms && (! nfReqAttrs.isEmpty()))
    {
      if (entryValid)
      {
        entryValid = false;
        nameFormViolations.incrementAndGet();
      }
      if (invalidReasons != null)
      {
        for (final AttributeTypeDefinition d : nfReqAttrs)
        {
          invalidReasons.add(ERR_ENTRY_RDN_MISSING_REQUIRED_ATTR.get(
               d.getNameOrOID()));
        }
      }
    }

    return entryValid;
  }


  private static void updateCount(final String key,
                           final ConcurrentHashMap<String,AtomicLong> map)
  {
    final String lowerKey = toLowerCase(key);
    AtomicLong l = map.get(lowerKey);
    if (l == null)
    {
      l = map.putIfAbsent(lowerKey, new AtomicLong(1L));
      if (l == null)
      {
        return;
      }
    }

    l.incrementAndGet();
  }


  public void resetCounts()
  {
    entriesExamined.set(0L);
    invalidEntries.set(0L);
    malformedDNs.set(0L);
    missingSuperiorClasses.set(0L);
    multipleStructuralClasses.set(0L);
    nameFormViolations.set(0L);
    noObjectClasses.set(0L);
    noStructuralClass.set(0L);

    attributesViolatingSyntax.clear();
    missingAttributes.clear();
    prohibitedAttributes.clear();
    prohibitedObjectClasses.clear();
    singleValueViolations.clear();
    undefinedAttributes.clear();
    undefinedObjectClasses.clear();
  }


  public long getEntriesExamined()
  {
    return entriesExamined.get();
  }


  public long getInvalidEntries()
  {
    return invalidEntries.get();
  }

  public long getMalformedDNs()
  {
    return malformedDNs.get();
  }

  public long getEntriesWithoutAnyObjectClasses()
  {
    return noObjectClasses.get();
  }

  public long getEntriesMissingStructuralObjectClass()
  {
    return noStructuralClass.get();
  }

  public long getEntriesWithMultipleStructuralObjectClasses()
  {
    return multipleStructuralClasses.get();
  }

  public long getEntriesWithMissingSuperiorObjectClasses()
  {
    return missingSuperiorClasses.get();
  }

  public long getNameFormViolations()
  {
    return nameFormViolations.get();
  }

  public long getTotalUndefinedObjectClasses()
  {
    return getMapTotal(undefinedObjectClasses);
  }

  public Map<String,Long> getUndefinedObjectClasses()
  {
    return convertMap(undefinedObjectClasses);
  }

  public long getTotalUndefinedAttributes()
  {
    return getMapTotal(undefinedAttributes);
  }

  public Map<String,Long> getUndefinedAttributes()
  {
    return convertMap(undefinedAttributes);
  }

  public long getTotalProhibitedObjectClasses()
  {
    return getMapTotal(prohibitedObjectClasses);
  }

  public Map<String,Long> getProhibitedObjectClasses()
  {
    return convertMap(prohibitedObjectClasses);
  }

  public long getTotalProhibitedAttributes()
  {
    return getMapTotal(prohibitedAttributes);
  }

  public Map<String,Long> getProhibitedAttributes()
  {
    return convertMap(prohibitedAttributes);
  }

  public long getTotalMissingAttributes()
  {
    return getMapTotal(missingAttributes);
  }

  public Map<String,Long> getMissingAttributes()
  {
    return convertMap(missingAttributes);
  }

  public long getTotalAttributesViolatingSyntax()
  {
    return getMapTotal(attributesViolatingSyntax);
  }

  public Map<String,Long> getAttributesViolatingSyntax()
  {
    return convertMap(attributesViolatingSyntax);
  }

  public long getTotalSingleValueViolations()
  {
    return getMapTotal(singleValueViolations);
  }

  public Map<String,Long> getSingleValueViolations()
  {
    return convertMap(singleValueViolations);
  }

  private static long getMapTotal(final Map<String,AtomicLong> map)
  {
    long total = 0L;

    for (final AtomicLong l : map.values())
    {
      total += l.longValue();
    }

    return total;
  }

  private static Map<String,Long> convertMap(final Map<String,AtomicLong> map)
  {
    final TreeMap<String,Long> m = new TreeMap<String,Long>();
    for (final Map.Entry<String,AtomicLong> e : map.entrySet())
    {
      m.put(e.getKey(), e.getValue().longValue());
    }

    return Collections.unmodifiableMap(m);
  }

  public List<String> getInvalidEntrySummary(final boolean detailedResults)
  {
    final long numInvalid = invalidEntries.get();
    if (numInvalid == 0)
    {
      return Collections.emptyList();
    }

    final ArrayList<String> messages = new ArrayList<String>(5);
    final long numEntries = entriesExamined.get();
    long pct = 100 * numInvalid / numEntries;
    messages.add(INFO_ENTRY_INVALID_ENTRY_COUNT.get(
         numInvalid, numEntries, pct));

    final long numBadDNs = malformedDNs.get();
    if (numBadDNs > 0)
    {
      pct = 100 * numBadDNs / numEntries;
      messages.add(INFO_ENTRY_MALFORMED_DN_COUNT.get(
           numBadDNs, numEntries, pct));
    }

    final long numNoOCs = noObjectClasses.get();
    if (numNoOCs > 0)
    {
      pct = 100 * numNoOCs / numEntries;
      messages.add(INFO_ENTRY_NO_OC_COUNT.get(numNoOCs, numEntries, pct));
    }

    final long numMissingStructural = noStructuralClass.get();
    if (numMissingStructural > 0)
    {
      pct = 100 * numMissingStructural / numEntries;
      messages.add(INFO_ENTRY_NO_STRUCTURAL_OC_COUNT.get(
           numMissingStructural, numEntries, pct));
    }

    final long numMultipleStructural = multipleStructuralClasses.get();
    if (numMultipleStructural > 0)
    {
      pct = 100 * numMultipleStructural / numEntries;
      messages.add(INFO_ENTRY_MULTIPLE_STRUCTURAL_OCS_COUNT.get(
           numMultipleStructural, numEntries, pct));
    }

    final long numNFViolations = nameFormViolations.get();
    if (numNFViolations > 0)
    {
      pct = 100 * numNFViolations / numEntries;
      messages.add(INFO_ENTRY_NF_VIOLATION_COUNT.get(
           numNFViolations, numEntries, pct));
    }

    final long numUndefinedOCs = getTotalUndefinedObjectClasses();
    if (numUndefinedOCs > 0)
    {
      messages.add(INFO_ENTRY_UNDEFINED_OC_COUNT.get(numUndefinedOCs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             undefinedObjectClasses.entrySet())
        {
          messages.add(INFO_ENTRY_UNDEFINED_OC_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numProhibitedOCs = getTotalProhibitedObjectClasses();
    if (numProhibitedOCs > 0)
    {
      messages.add(INFO_ENTRY_PROHIBITED_OC_COUNT.get(numProhibitedOCs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             prohibitedObjectClasses.entrySet())
        {
          messages.add(INFO_ENTRY_PROHIBITED_OC_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numMissingSuperior =
         getEntriesWithMissingSuperiorObjectClasses();
    if (numMissingSuperior > 0)
    {
      messages.add(
           INFO_ENTRY_MISSING_SUPERIOR_OC_COUNT.get(numMissingSuperior));
    }

    final long numUndefinedAttrs = getTotalUndefinedAttributes();
    if (numUndefinedAttrs > 0)
    {
      messages.add(INFO_ENTRY_UNDEFINED_ATTR_COUNT.get(numUndefinedAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             undefinedAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_UNDEFINED_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numMissingAttrs = getTotalMissingAttributes();
    if (numMissingAttrs > 0)
    {
      messages.add(INFO_ENTRY_MISSING_ATTR_COUNT.get(numMissingAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             missingAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_MISSING_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numProhibitedAttrs = getTotalProhibitedAttributes();
    if (numProhibitedAttrs > 0)
    {
      messages.add(INFO_ENTRY_PROHIBITED_ATTR_COUNT.get(numProhibitedAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             prohibitedAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_PROHIBITED_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numSingleValuedViolations = getTotalSingleValueViolations();
    if (numSingleValuedViolations > 0)
    {
      messages.add(INFO_ENTRY_SINGLE_VALUE_VIOLATION_COUNT.get(
           numSingleValuedViolations));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             singleValueViolations.entrySet())
        {
          messages.add(INFO_ENTRY_SINGLE_VALUE_VIOLATION_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numSyntaxViolations = getTotalAttributesViolatingSyntax();
    if (numSyntaxViolations > 0)
    {
      messages.add(INFO_ENTRY_SYNTAX_VIOLATION_COUNT.get(numSyntaxViolations));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             attributesViolatingSyntax.entrySet())
        {
          messages.add(INFO_ENTRY_SYNTAX_VIOLATION_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    return Collections.unmodifiableList(messages);
  }
}
