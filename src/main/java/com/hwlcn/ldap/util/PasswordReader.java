
package com.hwlcn.ldap.util;



import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;

import static com.hwlcn.ldap.util.UtilityMessages.*;


@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordReader
       extends Thread
{
  private final AtomicBoolean stopRequested;

  private final Object startMutex;


  private PasswordReader()
  {
    startMutex = new Object();
    stopRequested = new AtomicBoolean(false);

    setName("Password Reader Thread");
    setDaemon(true);
    setPriority(Thread.MAX_PRIORITY);
  }


  public static byte[] readPassword()
         throws LDAPException
  {
    try
    {
      final Method consoleMethod = System.class.getMethod("console");
      final Object consoleObject = consoleMethod.invoke(null);

      final Method readPasswordMethod =
        consoleObject.getClass().getMethod("readPassword");
      final char[] pwChars = (char[]) readPasswordMethod.invoke(consoleObject);

      final ByteStringBuffer buffer = new ByteStringBuffer();
      buffer.append(pwChars);
      Arrays.fill(pwChars, '\u0000');
      final byte[] pwBytes = buffer.toByteArray();
      buffer.clear(true);
      return pwBytes;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      final PasswordReader r = new PasswordReader();
      try
      {
        synchronized (r.startMutex)
        {
          r.start();
          r.startMutex.wait();
        }

        final ByteStringBuffer buffer = new ByteStringBuffer();
        while (true)
        {
          final int byteRead = System.in.read();
          if ((byteRead < 0) || (byteRead == 0x0A))
          {
            break;
          }
          else if (byteRead == 0x0D)
          {
            final int nextCharacter = System.in.read();
            if ((nextCharacter < 0) || (byteRead == 0x0A))
            {
              break;
            }
            else
            {
              buffer.append((byte) byteRead);
              buffer.append((byte) nextCharacter);
            }
          }
          else
          {
            buffer.append((byte) byteRead);
          }
        }

        final byte[] pwBytes = buffer.toByteArray();
        buffer.clear(true);
        return pwBytes;
      }
      finally
      {
        r.stopRequested.set(true);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_PW_READER_FAILURE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }


  @Override()
  public void run()
  {
    synchronized (startMutex)
    {
      startMutex.notifyAll();
    }

    while (! stopRequested.get())
    {
      System.out.print("\u0008 ");
      yield();
    }
  }
}
