
package com.hwlcn.security.crypto;

import com.hwlcn.security.util.StringUtils;


public class DefaultBlockCipherService extends AbstractSymmetricCipherService {

    private static final int DEFAULT_BLOCK_SIZE = 0;

    private static final String TRANSFORMATION_STRING_DELIMITER = "/";
    private static final int DEFAULT_STREAMING_BLOCK_SIZE = 8; //8 bits (1 byte)

    private String modeName;
    private int blockSize;
    private String paddingSchemeName;

    private String streamingModeName;
    private int streamingBlockSize;
    private String streamingPaddingSchemeName;

    private String transformationString;
    private String streamingTransformationString;


    public DefaultBlockCipherService(String algorithmName) {
        super(algorithmName);

        this.modeName = OperationMode.CBC.name();
        this.paddingSchemeName = PaddingScheme.PKCS5.getTransformationName();
        this.blockSize = DEFAULT_BLOCK_SIZE;

        this.streamingModeName = OperationMode.CBC.name();
        this.streamingPaddingSchemeName = PaddingScheme.PKCS5.getTransformationName();
        this.streamingBlockSize = DEFAULT_STREAMING_BLOCK_SIZE;
    }


    public String getModeName() {
        return modeName;
    }


    public void setModeName(String modeName) {
        this.modeName = modeName;

        this.transformationString = null;
    }


    public void setMode(OperationMode mode) {
        setModeName(mode.name());
    }


    public String getPaddingSchemeName() {
        return paddingSchemeName;
    }


    public void setPaddingSchemeName(String paddingSchemeName) {
        this.paddingSchemeName = paddingSchemeName;
        this.transformationString = null;
    }

    public void setPaddingScheme(PaddingScheme paddingScheme) {
        setPaddingSchemeName(paddingScheme.getTransformationName());
    }

     public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = Math.max(DEFAULT_BLOCK_SIZE, blockSize);
        this.transformationString = null;
    }

    public String getStreamingModeName() {
        return streamingModeName;
    }

    private boolean isModeStreamingCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    public void setStreamingModeName(String streamingModeName) {
        if (!isModeStreamingCompatible(streamingModeName)) {
            String msg = "mode [" + streamingModeName + "] is not a valid operation mode for block cipher streaming.";
            throw new IllegalArgumentException(msg);
        }
        this.streamingModeName = streamingModeName;
        this.streamingTransformationString = null;
    }

    public void setStreamingMode(OperationMode mode) {
        setStreamingModeName(mode.name());
    }

    public String getStreamingPaddingSchemeName() {
        return streamingPaddingSchemeName;
    }

    public void setStreamingPaddingSchemeName(String streamingPaddingSchemeName) {
        this.streamingPaddingSchemeName = streamingPaddingSchemeName;
        this.streamingTransformationString = null;
    }

    public void setStreamingPaddingScheme(PaddingScheme scheme) {
        setStreamingPaddingSchemeName(scheme.getTransformationName());
    }

    public int getStreamingBlockSize() {
        return streamingBlockSize;
    }

    public void setStreamingBlockSize(int streamingBlockSize) {
        this.streamingBlockSize = Math.max(DEFAULT_BLOCK_SIZE, streamingBlockSize);
        this.streamingTransformationString = null;
    }

    protected String getTransformationString(boolean streaming) {
        if (streaming) {
            if (this.streamingTransformationString == null) {
                this.streamingTransformationString = buildStreamingTransformationString();
            }
            return this.streamingTransformationString;
        } else {
            if (this.transformationString == null) {
                this.transformationString = buildTransformationString();
            }
            return this.transformationString;
        }
    }

    private String buildTransformationString() {
        return buildTransformationString(getModeName(), getPaddingSchemeName(), getBlockSize());
    }

    private String buildStreamingTransformationString() {
        return buildTransformationString(getStreamingModeName(), getStreamingPaddingSchemeName(), 0);
    }

    private String buildTransformationString(String modeName, String paddingSchemeName, int blockSize) {
        StringBuilder sb = new StringBuilder(getAlgorithmName());
        if (StringUtils.hasText(modeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(modeName);
        }
        if (blockSize > 0) {
            sb.append(blockSize);
        }
        if (StringUtils.hasText(paddingSchemeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(paddingSchemeName);
        }
        return sb.toString();
    }

    private boolean isModeInitializationVectorCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    @Override
    protected boolean isGenerateInitializationVectors(boolean streaming) {
        return streaming || super.isGenerateInitializationVectors() && isModeInitializationVectorCompatible(getModeName());
    }

    @Override
    protected byte[] generateInitializationVector(boolean streaming) {
        if (streaming) {
            String streamingModeName = getStreamingModeName();
            if (!isModeInitializationVectorCompatible(streamingModeName)) {
                String msg = "streamingMode attribute value [" + streamingModeName + "] does not support " +
                        "Initialization Vectors.  Ensure the streamingMode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        } else {
            String modeName = getModeName();
            if (!isModeInitializationVectorCompatible(modeName)) {
                String msg = "mode attribute value [" + modeName + "] does not support " +
                        "Initialization Vectors.  Ensure the mode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        }
        return super.generateInitializationVector(streaming);
    }
}
