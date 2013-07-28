package com.hwlcn.ldap.ldap.sdk;



import java.util.List;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;

@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class UpdatableLDAPRequest
       extends LDAPRequest
{

  private static final long serialVersionUID = 2487230102594573848L;

  protected UpdatableLDAPRequest(final Control[] controls)
  {
    super(controls);
  }


  public final void setControls(final Control... controls)
  {
    if (controls == null)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      setControlsInternal(controls);
    }
  }


  public final void setControls(final List<Control> controls)
  {
    if ((controls == null) || controls.isEmpty())
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] controlArray = new Control[controls.size()];
      setControlsInternal(controls.toArray(controlArray));
    }
  }


  public final void clearControls()
  {
    setControlsInternal(NO_CONTROLS);
  }



  public final void addControl(final Control control)
  {
    ensureNotNull(control);

    final Control[] controls = getControls();

    final Control[] newControls = new Control[controls.length+1];
    System.arraycopy(controls, 0, newControls, 0, controls.length);
    newControls[controls.length] = control;

    setControlsInternal(newControls);
  }



  public final void addControls(final Control... controls)
  {
    if ((controls == null) || (controls.length == 0))
    {
      return;
    }

    final Control[] currentControls = getControls();

    final Control[] newControls =
         new Control[currentControls.length + controls.length];
    System.arraycopy(currentControls, 0, newControls, 0,
                     currentControls.length);
    System.arraycopy(controls, 0, newControls, currentControls.length,
                     controls.length);

    setControlsInternal(newControls);
  }



  public final Control removeControl(final String oid)
  {
    ensureNotNull(oid);

    final Control[] controls = getControls();

    int pos = -1;
    Control c = null;
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].getOID().equals(oid))
      {
        c = controls[i];
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return null;
    }

    if (controls.length == 1)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] newControls = new Control[controls.length - 1];
      for (int i=0,j=0; i < controls.length; i++)
      {
        if (i != pos)
        {
          newControls[j++] = controls[i];
        }
      }
      setControlsInternal(newControls);
    }

    return c;
  }



  public final boolean removeControl(final Control control)
  {
    ensureNotNull(control);

    final Control[] controls = getControls();

    int pos = -1;
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].equals(control))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    if (controls.length == 1)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] newControls = new Control[controls.length - 1];
      for (int i=0,j=0; i < controls.length; i++)
      {
        if (i != pos)
        {
          newControls[j++] = controls[i];
        }
      }
      setControlsInternal(newControls);
    }

    return true;
  }



  public final Control replaceControl(final Control control)
  {
    ensureNotNull(control);

    return replaceControl(control.getOID(), control);
  }



  public final Control replaceControl(final String oid, final Control control)
  {
    ensureNotNull(oid);

    if (control == null)
    {
      return removeControl(oid);
    }

    final Control[] controls = getControls();
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].getOID().equals(oid))
      {
        final Control c = controls[i];
        controls[i] = control;
        setControlsInternal(controls);
        return c;
      }
    }

    final Control[] newControls = new Control[controls.length+1];
    System.arraycopy(controls, 0, newControls, 0, controls.length);
    newControls[controls.length] = control;
    setControlsInternal(newControls);
    return null;
  }
}
