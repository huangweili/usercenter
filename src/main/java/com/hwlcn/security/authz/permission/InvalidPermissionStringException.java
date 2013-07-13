package com.hwlcn.security.authz.permission;


public class InvalidPermissionStringException extends RuntimeException {

    private String permissionString;

    public InvalidPermissionStringException(String message, String permissionString) {
        super(message);
        this.permissionString = permissionString;
    }

    public String getPermissionString() {
        return this.permissionString;
    }


}
