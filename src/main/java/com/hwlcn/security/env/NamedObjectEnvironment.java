package com.hwlcn.security.env;


public interface NamedObjectEnvironment extends Environment {


    <T> T getObject(String name, Class<T> requiredType) throws RequiredTypeException;
}
