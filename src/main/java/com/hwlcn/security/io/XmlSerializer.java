package com.hwlcn.security.io;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;


public class XmlSerializer implements Serializer {

    public byte[] serialize(Object source) {
        if (source == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(bos));
        encoder.writeObject(source);
        encoder.close();

        return bos.toByteArray();
    }

    public Object deserialize(byte[] serialized) {
        if (serialized == null) {
            throw new IllegalArgumentException("Argument cannot be null.");
        }
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(bis));
        Object o = decoder.readObject();
        decoder.close();
        return o;
    }
}
