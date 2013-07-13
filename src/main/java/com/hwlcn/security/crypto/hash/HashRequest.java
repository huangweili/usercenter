package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.util.ByteSource;


public interface HashRequest {

    ByteSource getSource();

    ByteSource getSalt();


    int getIterations();

    String getAlgorithmName();

    public static class Builder {

        private ByteSource source;
        private ByteSource salt;
        private int iterations;
        private String algorithmName;

        /**
         * Default no-arg constructor.
         */
        public Builder() {
            this.iterations = 0;
        }

        /**
         * Sets the source data that will be hashed by a {@link HashService}. For example, this might be a
         * {@code ByteSource} representation of a password, or file, etc.
         *
         * @param source the source data that will be hashed by a {@link HashService}.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getSource()
         * @see #setSource(Object)
         */
        public Builder setSource(ByteSource source) {
            this.source = source;
            return this;
        }

        /**
         * Sets the source data that will be hashed by a {@link HashService}.
         * <p/>
         * This is a convenience alternative to {@link #setSource(com.hwlcn.security.util.ByteSource)}: it will attempt to convert the
         * argument into a {@link com.hwlcn.security.util.ByteSource} instance using Shiro's default conversion heuristics
         * (as defined by {@link com.hwlcn.security.util.ByteSource.Util#isCompatible(Object) ByteSource.Util.isCompatible}.  If the object
         * cannot be heuristically converted to a {@code ByteSource}, an {@code IllegalArgumentException} will be
         * thrown.
         *
         * @param source the byte-backed source data that will be hashed by a {@link HashService}.
         * @return this {@code Builder} instance for method chaining.
         * @throws IllegalArgumentException if the argument cannot be heuristically converted to a {@link com.hwlcn.security.util.ByteSource}
         *                                  instance.
         * @see HashRequest#getSource()
         * @see #setSource(com.hwlcn.security.util.ByteSource)
         */
        public Builder setSource(Object source) throws IllegalArgumentException {
            this.source = ByteSource.Util.bytes(source);
            return this;
        }

        /**
         * Sets a salt to be used by the {@link HashService} during hash computation.
         * <p/>
         * <b>NOTE</b>: not calling this method does not necessarily mean a salt won't be used at all - it just
         * means that the request didn't include a salt.  The servicing {@link HashService} is free to provide a salting
         * strategy for a request, even if the request did not specify one.  You can always check the result
         * {@code Hash} {@link Hash#getSalt() getSalt()} method to see what the actual
         * salt was (if any), which may or may not match this request salt.
         *
         * @param salt a salt to be used by the {@link HashService} during hash computation
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getSalt()
         */
        public Builder setSalt(ByteSource salt) {
            this.salt = salt;
            return this;
        }

        /**
         * Sets a salt to be used by the {@link HashService} during hash computation.
         * <p/>
         * This is a convenience alternative to {@link #setSalt(com.hwlcn.security.util.ByteSource)}: it will attempt to convert the
         * argument into a {@link com.hwlcn.security.util.ByteSource} instance using Shiro's default conversion heuristics
         * (as defined by {@link com.hwlcn.security.util.ByteSource.Util#isCompatible(Object) ByteSource.Util.isCompatible}.  If the object
         * cannot be heuristically converted to a {@code ByteSource}, an {@code IllegalArgumentException} will be
         * thrown.
         *
         * @param salt a salt to be used by the {@link HashService} during hash computation.
         * @return this {@code Builder} instance for method chaining.
         * @throws IllegalArgumentException if the argument cannot be heuristically converted to a {@link com.hwlcn.security.util.ByteSource}
         *                                  instance.
         * @see #setSalt(com.hwlcn.security.util.ByteSource)
         * @see HashRequest#getSalt()
         */
        public Builder setSalt(Object salt) throws IllegalArgumentException {
            this.salt = ByteSource.Util.bytes(salt);
            return this;
        }

        /**
         * Sets the number of requested hash iterations to be performed when computing the final {@code Hash} result.
         * Not calling this method or setting a non-positive value (0 or less) indicates that the {@code HashService}'s
         * default iteration configuration should be used.  A positive value overrides the {@code HashService}'s
         * configuration for a single request.
         * <p/>
         * Note that a {@code HashService} is free to ignore this number if it determines the number is not sufficient
         * to meet a desired level of security. You can always check the result
         * {@code Hash} {@link Hash#getIterations() getIterations()} method to see what the actual
         * number of iterations was, which may or may not match this request salt.
         *
         * @param iterations the number of requested hash iterations to be performed when computing the final
         *                   {@code Hash} result.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getIterations()
         */
        public Builder setIterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Sets the name of the hash algorithm the {@code HashService} should use when computing the {@link Hash}.
         * Not calling this method or setting it to {@code null} indicates the the default algorithm configuration of
         * the {@code HashService} should be used.  A non-null value
         * overrides the {@code HashService}'s configuration for a single request.
         * <p/>
         * Note that a {@code HashService} is free to ignore this value if it determines that the algorithm is not
         * sufficient to meet a desired level of security. You can always check the result
         * {@code Hash} {@link Hash#getAlgorithmName() getAlgorithmName()} method to see what the actual
         * algorithm was, which may or may not match this request salt.
         *
         * @param algorithmName the name of the hash algorithm the {@code HashService} should use when computing the
         *                      {@link Hash}, or {@code null} if the default algorithm configuration of the
         *                      {@code HashService} should be used.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getAlgorithmName()
         */
        public Builder setAlgorithmName(String algorithmName) {
            this.algorithmName = algorithmName;
            return this;
        }

        /**
         * Builds a {@link HashRequest} instance reflecting the specified configuration.
         *
         * @return a {@link HashRequest} instance reflecting the specified configuration.
         */
        public HashRequest build() {
            return new SimpleHashRequest(this.algorithmName, this.source, this.salt, this.iterations);
        }
    }
}
