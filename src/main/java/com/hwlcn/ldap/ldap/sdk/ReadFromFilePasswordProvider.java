package com.hwlcn.ldap.ldap.sdk;



import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReadFromFilePasswordProvider
       extends PasswordProvider
       implements Serializable
{
  private static final long serialVersionUID = -3343425971796985100L;

  private final File passwordFile;

  public ReadFromFilePasswordProvider(final String passwordFile)
  {
    Validator.ensureNotNull(passwordFile);

    this.passwordFile = new File(passwordFile);
  }


  public ReadFromFilePasswordProvider(final File passwordFile)
  {
    Validator.ensureNotNull(passwordFile);

    this.passwordFile = passwordFile;
  }



  @Override()
  public byte[] getPasswordBytes()
         throws LDAPException
  {
    byte[] pwBytes = null;

    try
    {
      final int fileLength = (int) passwordFile.length();
      pwBytes = new byte[fileLength];

      final FileInputStream inputStream = new FileInputStream(passwordFile);

      try
      {
        int pos = 0;
        while (pos < fileLength)
        {
          final int bytesRead =
               inputStream.read(pwBytes, pos, pwBytes.length - pos);
          if (bytesRead < 0)
          {
            break;
          }

          pos += bytesRead;
        }
      }
      finally
      {
        inputStream.close();
      }

       for (int i=0; i < pwBytes.length; i++)
      {
        if ((pwBytes[i] == '\n') || (pwBytes[i] == '\r'))
        {
          final byte[] pwWithoutEOL = new byte[i];
          System.arraycopy(pwBytes, 0, pwWithoutEOL, 0, i);
          Arrays.fill(pwBytes, (byte) 0x00);
          pwBytes = pwWithoutEOL;
          break;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (pwBytes != null)
      {
        Arrays.fill(pwBytes, (byte) 0x00);
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_FILE_PW_PROVIDER_ERROR_READING_PW.get(
                passwordFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (pwBytes.length == 0)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_FILE_PW_PROVIDER_EMPTY_PW.get(passwordFile.getAbsolutePath()));
    }

    return pwBytes;
  }
}
