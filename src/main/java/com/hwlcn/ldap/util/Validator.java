package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.UtilityMessages.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Validator
{

  private Validator()
  {
  }


  public static void ensureNotNull(final Object o)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(0,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureNotNullWithMessage(final Object o,
                                              final String message)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureNotNull(final Object o1, final Object o2)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else
      {
        index = 1;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }




  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else
      {
        index = 2;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3, final Object o4)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null) || (o4 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else if (o3 == null)
      {
        index = 2;
      }
      else
      {
        index = 3;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3, final Object o4,
                                   final Object o5)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null) || (o4 == null) ||
        (o5 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else if (o3 == null)
      {
        index = 2;
      }
      else if (o4 == null)
      {
        index = 3;
      }
      else
      {
        index = 4;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }


  public static void ensureTrue(final boolean condition)
         throws LDAPSDKUsageException
  {
    if (! condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_TRUE_CHECK_FAILURE.get(
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureTrue(final boolean condition, final String message)
         throws LDAPSDKUsageException
  {
    if (! condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  public static void ensureFalse(final boolean condition)
         throws LDAPSDKUsageException
  {
    if (condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FALSE_CHECK_FAILURE.get(
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }


  public static void ensureFalse(final boolean condition, final String message)
         throws LDAPSDKUsageException
  {
    if (condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }
}
