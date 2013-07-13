
package com.hwlcn.security.realm.text;

import com.hwlcn.security.authc.SimpleAccount;
import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.authz.SimpleRole;
import com.hwlcn.security.config.ConfigurationException;
import com.hwlcn.security.realm.SimpleAccountRealm;
import com.hwlcn.security.util.PermissionUtils;
import com.hwlcn.security.util.StringUtils;

import java.text.ParseException;
import java.util.*;
public class TextConfigurationRealm extends SimpleAccountRealm {

    private volatile String userDefinitions;
    private volatile String roleDefinitions;

    public TextConfigurationRealm() {
        super();
    }

    @Override
    protected void onInit() {
        super.onInit();
        processDefinitions();
    }

    public String getUserDefinitions() {
        return userDefinitions;
    }


    public void setUserDefinitions(String userDefinitions) {
        this.userDefinitions = userDefinitions;
    }

    public String getRoleDefinitions() {
        return roleDefinitions;
    }
  public void setRoleDefinitions(String roleDefinitions) {
        this.roleDefinitions = roleDefinitions;
    }

    protected void processDefinitions() {
        try {
            processRoleDefinitions();
            processUserDefinitions();
        } catch (ParseException e) {
            String msg = "Unable to parse user and/or role definitions.";
            throw new ConfigurationException(msg, e);
        }
    }

    protected void processRoleDefinitions() throws ParseException {
        String roleDefinitions = getRoleDefinitions();
        if (roleDefinitions == null) {
            return;
        }
        Map<String, String> roleDefs = toMap(toLines(roleDefinitions));
        processRoleDefinitions(roleDefs);
    }

    protected void processRoleDefinitions(Map<String, String> roleDefs) {
        if (roleDefs == null || roleDefs.isEmpty()) {
            return;
        }
        for (String rolename : roleDefs.keySet()) {
            String value = roleDefs.get(rolename);

            SimpleRole role = getRole(rolename);
            if (role == null) {
                role = new SimpleRole(rolename);
                add(role);
            }

            Set<Permission> permissions = PermissionUtils.resolveDelimitedPermissions(value, getPermissionResolver());
            role.setPermissions(permissions);
        }
    }

    protected void processUserDefinitions() throws ParseException {
        String userDefinitions = getUserDefinitions();
        if (userDefinitions == null) {
            return;
        }

        Map<String, String> userDefs = toMap(toLines(userDefinitions));

        processUserDefinitions(userDefs);
    }

    protected void processUserDefinitions(Map<String, String> userDefs) {
        if (userDefs == null || userDefs.isEmpty()) {
            return;
        }
        for (String username : userDefs.keySet()) {

            String value = userDefs.get(username);

            String[] passwordAndRolesArray = StringUtils.split(value);

            String password = passwordAndRolesArray[0];

            SimpleAccount account = getUser(username);
            if (account == null) {
                account = new SimpleAccount(username, password, getName());
                add(account);
            }
            account.setCredentials(password);

            if (passwordAndRolesArray.length > 1) {
                for (int i = 1; i < passwordAndRolesArray.length; i++) {
                    String rolename = passwordAndRolesArray[i];
                    account.addRole(rolename);

                    SimpleRole role = getRole(rolename);
                    if (role != null) {
                        account.addObjectPermissions(role.getPermissions());
                    }
                }
            } else {
                account.setRoles(null);
            }
        }
    }

    protected static Set<String> toLines(String s) {
        LinkedHashSet<String> set = new LinkedHashSet<String>();
        Scanner scanner = new Scanner(s);
        while (scanner.hasNextLine()) {
            set.add(scanner.nextLine());
        }
        return set;
    }

    protected static Map<String, String> toMap(Collection<String> keyValuePairs) throws ParseException {
        if (keyValuePairs == null || keyValuePairs.isEmpty()) {
            return null;
        }

        Map<String, String> pairs = new HashMap<String, String>();
        for (String pairString : keyValuePairs) {
            String[] pair = StringUtils.splitKeyValue(pairString);
            if (pair != null) {
                pairs.put(pair[0].trim(), pair[1].trim());
            }
        }

        return pairs;
    }
}
