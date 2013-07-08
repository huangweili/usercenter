package com.hwlcn.ldap.asn1;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.ldap.util.Mutable;
import com.hwlcn.ldap.util.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;


@Mutable()
@ThreadSafety(level = ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1Buffer
        implements Serializable {
    private static final int DEFAULT_MAX_BUFFER_SIZE = 1048576;

    private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_ONE =
            {(byte) 0x81, (byte) 0x00};

    private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_TWO =
            {(byte) 0x82, (byte) 0x00, (byte) 0x00};

    private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_THREE =
            {(byte) 0x83, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_FOUR =
            {(byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};


    private static final long serialVersionUID = -4898230771376551562L;

    private final AtomicBoolean zeroBufferOnClear;

    private final ByteStringBuffer buffer;

    private final int maxBufferSize;


    public ASN1Buffer() {
        this(DEFAULT_MAX_BUFFER_SIZE);
    }


    public ASN1Buffer(final int maxBufferSize) {
        this.maxBufferSize = maxBufferSize;

        buffer = new ByteStringBuffer();
        zeroBufferOnClear = new AtomicBoolean(false);
    }


    public boolean zeroBufferOnClear() {
        return zeroBufferOnClear.get();
    }

    public void setZeroBufferOnClear() {
        zeroBufferOnClear.set(true);
    }

    public void clear() {
        buffer.clear(zeroBufferOnClear.getAndSet(false));

        if ((maxBufferSize > 0) && (buffer.capacity() > maxBufferSize)) {
            buffer.setCapacity(maxBufferSize);
        }
    }


    public int length() {
        return buffer.length();
    }


    public void addElement(final ASN1Element element) {
        element.encodeTo(buffer);
    }

    public void addBoolean(final boolean booleanValue) {
        addBoolean(ASN1Constants.UNIVERSAL_BOOLEAN_TYPE, booleanValue);
    }


    public void addBoolean(final byte type, final boolean booleanValue) {
        buffer.append(type);
        buffer.append((byte) 0x01);

        if (booleanValue) {
            buffer.append((byte) 0xFF);
        } else {
            buffer.append((byte) 0x00);
        }
    }

    public void addEnumerated(final int intValue) {
        addInteger(ASN1Constants.UNIVERSAL_ENUMERATED_TYPE, intValue);
    }


    public void addEnumerated(final byte type, final int intValue) {
        addInteger(type, intValue);
    }


    public void addInteger(final int intValue) {
        addInteger(ASN1Constants.UNIVERSAL_INTEGER_TYPE, intValue);
    }


    public void addInteger(final byte type, final int intValue) {
        buffer.append(type);

        if (intValue < 0) {
            if ((intValue & 0xFFFFFF80) == 0xFFFFFF80) {
                buffer.append((byte) 0x01);
                buffer.append((byte) (intValue & 0xFF));
            } else if ((intValue & 0xFFFF8000) == 0xFFFF8000) {
                buffer.append((byte) 0x02);
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
            } else if ((intValue & 0xFF800000) == 0xFF800000) {
                buffer.append((byte) 0x03);
                buffer.append((byte) ((intValue >> 16) & 0xFF));
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
            } else {
                buffer.append((byte) 0x04);
                buffer.append((byte) ((intValue >> 24) & 0xFF));
                buffer.append((byte) ((intValue >> 16) & 0xFF));
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
            }
        } else {
            if ((intValue & 0x0000007F) == intValue) {
                buffer.append((byte) 0x01);
                buffer.append((byte) (intValue & 0x7F));
            } else if ((intValue & 0x00007FFF) == intValue) {
                buffer.append((byte) 0x02);
                buffer.append((byte) ((intValue >> 8) & 0x7F));
                buffer.append((byte) (intValue & 0xFF));
            } else if ((intValue & 0x007FFFFF) == intValue) {
                buffer.append((byte) 0x03);
                buffer.append((byte) ((intValue >> 16) & 0x7F));
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
            } else {
                buffer.append((byte) 0x04);
                buffer.append((byte) ((intValue >> 24) & 0x7F));
                buffer.append((byte) ((intValue >> 16) & 0xFF));
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
            }
        }
    }


    public void addInteger(final long longValue) {
        addInteger(ASN1Constants.UNIVERSAL_INTEGER_TYPE, longValue);
    }


    public void addInteger(final byte type, final long longValue) {
        buffer.append(type);

        if (longValue < 0) {
            if ((longValue & 0xFFFFFFFFFFFFFF80L) == 0xFFFFFFFFFFFFFF80L) {
                buffer.append((byte) 0x01);
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFFFFFFFFFFFF8000L) == 0xFFFFFFFFFFFF8000L) {
                buffer.append((byte) 0x02);
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFFFFFFFFFF800000L) == 0xFFFFFFFFFF800000L) {
                buffer.append((byte) 0x03);
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFFFFFFFF80000000L) == 0xFFFFFFFF80000000L) {
                buffer.append((byte) 0x04);
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFFFFFF8000000000L) == 0xFFFFFF8000000000L) {
                buffer.append((byte) 0x05);
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFFFF800000000000L) == 0xFFFF800000000000L) {
                buffer.append((byte) 0x06);
                buffer.append((byte) ((longValue >> 40) & 0xFFL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0xFF80000000000000L) == 0xFF80000000000000L) {
                buffer.append((byte) 0x07);
                buffer.append((byte) ((longValue >> 48) & 0xFFL));
                buffer.append((byte) ((longValue >> 40) & 0xFFL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else {
                buffer.append((byte) 0x08);
                buffer.append((byte) ((longValue >> 56) & 0xFFL));
                buffer.append((byte) ((longValue >> 48) & 0xFFL));
                buffer.append((byte) ((longValue >> 40) & 0xFFL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            }
        } else {
            if ((longValue & 0x000000000000007FL) == longValue) {
                buffer.append((byte) 0x01);
                buffer.append((byte) (longValue & 0x7FL));
            } else if ((longValue & 0x0000000000007FFFL) == longValue) {
                buffer.append((byte) 0x02);
                buffer.append((byte) ((longValue >> 8) & 0x7FL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0x00000000007FFFFFL) == longValue) {
                buffer.append((byte) 0x03);
                buffer.append((byte) ((longValue >> 16) & 0x7FL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0x000000007FFFFFFFL) == longValue) {
                buffer.append((byte) 0x04);
                buffer.append((byte) ((longValue >> 24) & 0x7FL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0x0000007FFFFFFFFFL) == longValue) {
                buffer.append((byte) 0x05);
                buffer.append((byte) ((longValue >> 32) & 0x7FL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0x00007FFFFFFFFFFFL) == longValue) {
                buffer.append((byte) 0x06);
                buffer.append((byte) ((longValue >> 40) & 0x7FL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else if ((longValue & 0x007FFFFFFFFFFFFFL) == longValue) {
                buffer.append((byte) 0x07);
                buffer.append((byte) ((longValue >> 48) & 0x7FL));
                buffer.append((byte) ((longValue >> 40) & 0xFFL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            } else {
                buffer.append((byte) 0x08);
                buffer.append((byte) ((longValue >> 56) & 0x7FL));
                buffer.append((byte) ((longValue >> 48) & 0xFFL));
                buffer.append((byte) ((longValue >> 40) & 0xFFL));
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                buffer.append((byte) (longValue & 0xFFL));
            }
        }
    }


    public void addNull() {
        addNull(ASN1Constants.UNIVERSAL_NULL_TYPE);
    }


    public void addNull(final byte type) {
        buffer.append(type);
        buffer.append((byte) 0x00);
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the default BER
     * type and no value.
     */
    public void addOctetString() {
        addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE);
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the provided BER
     * type and no value.
     *
     * @param type The BER type to use for the octet string element.
     */
    public void addOctetString(final byte type) {
        buffer.append(type);
        buffer.append((byte) 0x00);
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the default BER
     * type.
     *
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final byte[] value) {
        addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE, value);
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the default BER
     * type.
     *
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final CharSequence value) {
        if (value == null) {
            addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE);
        } else {
            addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE,
                    value.toString());
        }
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the default BER
     * type.
     *
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final String value) {
        addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE, value);
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the provided BER
     * type.
     *
     * @param type  The BER type to use for the octet string element.
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final byte type, final byte[] value) {
        buffer.append(type);

        if (value == null) {
            buffer.append((byte) 0x00);
        } else {
            ASN1Element.encodeLengthTo(value.length, buffer);
            buffer.append(value);
        }
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the provided BER
     * type.
     *
     * @param type  The BER type to use for the octet string element.
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final byte type, final CharSequence value) {
        if (value == null) {
            addOctetString(type);
        } else {
            addOctetString(type, value.toString());
        }
    }


    /**
     * Adds an octet string element to this ASN.1 buffer using the provided BER
     * type.
     *
     * @param type  The BER type to use for the octet string element.
     * @param value The value to use for the octet string element.
     */
    public void addOctetString(final byte type, final String value) {
        buffer.append(type);

        if (value == null) {
            buffer.append((byte) 0x00);
        } else {
            // We'll assume that the string contains only ASCII characters and
            // therefore the number of bytes will equal the number of characters.
            // However, save the position in case we're wrong and need to re-encode.
            final int lengthStartPos = buffer.length();
            ASN1Element.encodeLengthTo(value.length(), buffer);

            final int valueStartPos = buffer.length();
            buffer.append(value);

            if (buffer.length() != (valueStartPos + value.length())) {
                final byte[] valueBytes = new byte[buffer.length() - valueStartPos];
                System.arraycopy(buffer.getBackingArray(), valueStartPos, valueBytes, 0,
                        valueBytes.length);

                buffer.setLength(lengthStartPos);
                ASN1Element.encodeLengthTo(valueBytes.length, buffer);
                buffer.append(valueBytes);
            }
        }
    }


    /**
     * Begins adding elements to an ASN.1 sequence using the default BER type.
     *
     * @return An object that may be used to indicate when the end of the
     *         sequence has been reached.  Once all embedded sequence elements
     *         have been added, then the {@link ASN1BufferSequence#end} method
     *         MUST be called to ensure that the sequence is properly encoded.
     */
    public ASN1BufferSequence beginSequence() {
        return beginSequence(ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
    }


    /**
     * Begins adding elements to an ASN.1 sequence using the provided BER type.
     *
     * @param type The BER type to use for the sequence.
     * @return An object that may be used to indicate when the end of the
     *         sequence has been reached.  Once all embedded sequence elements
     *         have been added, then the {@link ASN1BufferSequence#end} method
     *         MUST be called to ensure that the sequence is properly encoded.
     */
    public ASN1BufferSequence beginSequence(final byte type) {
        buffer.append(type);
        return new ASN1BufferSequence(this);
    }


    /**
     * Begins adding elements to an ASN.1 set using the default BER type.
     *
     * @return An object that may be used to indicate when the end of the set has
     *         been reached.  Once all embedded set elements have been added,
     *         then the {@link ASN1BufferSet#end} method MUST be called to ensure
     *         that the set is properly encoded.
     */
    public ASN1BufferSet beginSet() {
        return beginSet(ASN1Constants.UNIVERSAL_SET_TYPE);
    }


    /**
     * Begins adding elements to an ASN.1 set using the provided BER type.
     *
     * @param type The BER type to use for the set.
     * @return An object that may be used to indicate when the end of the set has
     *         been reached.  Once all embedded set elements have been added,
     *         then the {@link ASN1BufferSet#end} method MUST be called to ensure
     *         that the set is properly encoded.
     */
    public ASN1BufferSet beginSet(final byte type) {
        buffer.append(type);
        return new ASN1BufferSet(this);
    }


    /**
     * Ensures that the appropriate length is inserted into the internal buffer
     * after all elements in a sequence or set have been added.
     *
     * @param valueStartPos The position in which the first value was added.
     */
    void endSequenceOrSet(final int valueStartPos) {
        final int length = buffer.length() - valueStartPos;
        if (length == 0) {
            buffer.append((byte) 0x00);
            return;
        }

        if ((length & 0x7F) == length) {
            buffer.insert(valueStartPos, (byte) length);
        } else if ((length & 0xFF) == length) {
            buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_ONE);

            final byte[] backingArray = buffer.getBackingArray();
            backingArray[valueStartPos + 1] = (byte) (length & 0xFF);
        } else if ((length & 0xFFFF) == length) {
            buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_TWO);

            final byte[] backingArray = buffer.getBackingArray();
            backingArray[valueStartPos + 1] = (byte) ((length >> 8) & 0xFF);
            backingArray[valueStartPos + 2] = (byte) (length & 0xFF);
        } else if ((length & 0xFFFFFF) == length) {
            buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_THREE);

            final byte[] backingArray = buffer.getBackingArray();
            backingArray[valueStartPos + 1] = (byte) ((length >> 16) & 0xFF);
            backingArray[valueStartPos + 2] = (byte) ((length >> 8) & 0xFF);
            backingArray[valueStartPos + 3] = (byte) (length & 0xFF);
        } else {
            buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_FOUR);

            final byte[] backingArray = buffer.getBackingArray();
            backingArray[valueStartPos + 1] = (byte) ((length >> 24) & 0xFF);
            backingArray[valueStartPos + 2] = (byte) ((length >> 16) & 0xFF);
            backingArray[valueStartPos + 3] = (byte) ((length >> 8) & 0xFF);
            backingArray[valueStartPos + 4] = (byte) (length & 0xFF);
        }
    }


    /**
     * Writes the contents of this buffer to the provided output stream.
     *
     * @param outputStream The output stream to which the data should be
     *                     written.
     * @throws java.io.IOException If a problem occurs while writing to the provided
     *                             output stream.
     */
    public void writeTo(final OutputStream outputStream)
            throws IOException {
        if (debugEnabled(DebugType.ASN1)) {
            debugASN1Write(this);
        }

        buffer.write(outputStream);
    }


    /**
     * Retrieves a byte array containing the contents of this ASN.1 buffer.
     *
     * @return A byte array containing the contents of this ASN.1 buffer.
     */
    public byte[] toByteArray() {
        return buffer.toByteArray();
    }


    /**
     * Retrieves a byte buffer that wraps the data associated with this ASN.1
     * buffer.  The position will be set to the beginning of the data, and the
     * limit will be set to one byte after the end of the data.  The contents
     * of the returned byte buffer must not be altered in any way, and the
     * contents of this ASN.1 buffer must not be altered until the
     * {@code ByteBuffer} is no longer needed.
     *
     * @return A byte buffer that wraps the data associated with this ASN.1
     *         buffer.
     */
    public ByteBuffer asByteBuffer() {
        return ByteBuffer.wrap(buffer.getBackingArray(), 0, buffer.length());
    }
}
