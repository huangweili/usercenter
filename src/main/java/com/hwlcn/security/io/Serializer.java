package com.hwlcn.security.io;

public interface Serializer<T> {


    byte[] serialize(T o) throws SerializationException;

    T deserialize(byte[] serialized) throws SerializationException;
}
