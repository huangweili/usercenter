package com.hwlcn.ldap.ldap.sdk;


import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.ensureTrue;

@Mutable()
@ThreadSafety(level = ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPConnectionOptions {

    static final boolean DEFAULT_ABANDON_ON_TIMEOUT = false;


    static final boolean DEFAULT_AUTO_RECONNECT = false;


    static final boolean DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD = true;


    static final boolean DEFAULT_CAPTURE_CONNECT_STACK_TRACE = false;


    static final boolean DEFAULT_FOLLOW_REFERRALS = false;


    static final boolean DEFAULT_USE_POOLED_SCHEMA = false;


    static final boolean DEFAULT_USE_KEEPALIVE = true;


    static final boolean DEFAULT_USE_LINGER = true;


    static final boolean DEFAULT_USE_REUSE_ADDRESS = true;


    static final boolean DEFAULT_USE_SCHEMA = false;

    static final boolean DEFAULT_USE_SYNCHRONOUS_MODE = false;

    static final boolean DEFAULT_USE_TCP_NODELAY = true;

    static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 60000;

    static final int DEFAULT_LINGER_TIMEOUT_SECONDS = 5;

    static final int DEFAULT_MAX_MESSAGE_SIZE = 20971520;

    static final int DEFAULT_RECEIVE_BUFFER_SIZE = 0;

    static final int DEFAULT_REFERRAL_HOP_LIMIT = 5;

    static final int DEFAULT_SEND_BUFFER_SIZE = 0;

    static final long DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS = 3600000L;

    static final long DEFAULT_RESPONSE_TIMEOUT_MILLIS = 300000L;

    static final boolean DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE;

    static {
        final String vmVendor =
                StaticUtils.toLowerCase(System.getProperty("java.vm.vendor"));
        DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE = ((vmVendor != null) &&
                (vmVendor.contains("sun microsystems") ||
                        vmVendor.contains("oracle") ||
                        vmVendor.contains("apple")));
    }


    private boolean abandonOnTimeout;

    private boolean allowConcurrentSocketFactoryUse;

    private boolean autoReconnect;
    private boolean bindWithDNRequiresPassword;
    private boolean captureConnectStackTrace;

    private boolean followReferrals;

    private boolean useKeepAlive;

    private boolean useLinger;

    private boolean useReuseAddress;

    private boolean usePooledSchema;

    private boolean useSchema;
    private boolean useSynchronousMode;

    private boolean useTCPNoDelay;
    private DisconnectHandler disconnectHandler;

    private int connectTimeout;

    private int lingerTimeout;

    private int maxMessageSize;

    private int receiveBufferSize;

    private int referralHopLimit;
    private int sendBufferSize;

    private long pooledSchemaTimeout;

    private long responseTimeout;

    private ReferralConnector referralConnector;

    private UnsolicitedNotificationHandler unsolicitedNotificationHandler;

    public LDAPConnectionOptions() {
        abandonOnTimeout = DEFAULT_ABANDON_ON_TIMEOUT;
        autoReconnect = DEFAULT_AUTO_RECONNECT;
        bindWithDNRequiresPassword = DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD;
        captureConnectStackTrace = DEFAULT_CAPTURE_CONNECT_STACK_TRACE;
        followReferrals = DEFAULT_FOLLOW_REFERRALS;
        useKeepAlive = DEFAULT_USE_KEEPALIVE;
        useLinger = DEFAULT_USE_LINGER;
        useReuseAddress = DEFAULT_USE_REUSE_ADDRESS;
        usePooledSchema = DEFAULT_USE_POOLED_SCHEMA;
        useSchema = DEFAULT_USE_SCHEMA;
        useSynchronousMode = DEFAULT_USE_SYNCHRONOUS_MODE;
        useTCPNoDelay = DEFAULT_USE_TCP_NODELAY;
        connectTimeout = DEFAULT_CONNECT_TIMEOUT_MILLIS;
        lingerTimeout = DEFAULT_LINGER_TIMEOUT_SECONDS;
        maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;
        referralHopLimit = DEFAULT_REFERRAL_HOP_LIMIT;
        pooledSchemaTimeout = DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS;
        responseTimeout = DEFAULT_RESPONSE_TIMEOUT_MILLIS;
        receiveBufferSize = DEFAULT_RECEIVE_BUFFER_SIZE;
        sendBufferSize = DEFAULT_SEND_BUFFER_SIZE;
        disconnectHandler = null;
        referralConnector = null;
        unsolicitedNotificationHandler = null;

        allowConcurrentSocketFactoryUse =
                DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE;
    }


    public LDAPConnectionOptions duplicate() {
        final LDAPConnectionOptions o = new LDAPConnectionOptions();

        o.abandonOnTimeout = abandonOnTimeout;
        o.allowConcurrentSocketFactoryUse = allowConcurrentSocketFactoryUse;
        o.autoReconnect = autoReconnect;
        o.bindWithDNRequiresPassword = bindWithDNRequiresPassword;
        o.captureConnectStackTrace = captureConnectStackTrace;
        o.followReferrals = followReferrals;
        o.useKeepAlive = useKeepAlive;
        o.useLinger = useLinger;
        o.useReuseAddress = useReuseAddress;
        o.usePooledSchema = usePooledSchema;
        o.useSchema = useSchema;
        o.useSynchronousMode = useSynchronousMode;
        o.useTCPNoDelay = useTCPNoDelay;
        o.connectTimeout = connectTimeout;
        o.lingerTimeout = lingerTimeout;
        o.maxMessageSize = maxMessageSize;
        o.pooledSchemaTimeout = pooledSchemaTimeout;
        o.responseTimeout = responseTimeout;
        o.referralConnector = referralConnector;
        o.referralHopLimit = referralHopLimit;
        o.disconnectHandler = disconnectHandler;
        o.unsolicitedNotificationHandler = unsolicitedNotificationHandler;
        o.receiveBufferSize = receiveBufferSize;
        o.sendBufferSize = sendBufferSize;

        return o;
    }



    public boolean autoReconnect() {
        return autoReconnect;
    }


    public void setAutoReconnect(final boolean autoReconnect) {
        this.autoReconnect = autoReconnect;
    }


    public boolean bindWithDNRequiresPassword() {
        return bindWithDNRequiresPassword;
    }


    public void setBindWithDNRequiresPassword(
            final boolean bindWithDNRequiresPassword) {
        this.bindWithDNRequiresPassword = bindWithDNRequiresPassword;
    }



    public boolean captureConnectStackTrace() {
        return captureConnectStackTrace;
    }


    public void setCaptureConnectStackTrace(
            final boolean captureConnectStackTrace) {
        this.captureConnectStackTrace = captureConnectStackTrace;
    }


    public int getConnectTimeoutMillis() {
        return connectTimeout;
    }


    public void setConnectTimeoutMillis(final int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }



    public long getResponseTimeoutMillis() {
        return responseTimeout;
    }



    public void setResponseTimeoutMillis(final long responseTimeout) {
        if (responseTimeout < 0) {
            this.responseTimeout = 0L;
        } else {
            this.responseTimeout = responseTimeout;
        }
    }


    public boolean abandonOnTimeout() {
        return abandonOnTimeout;
    }



    public void setAbandonOnTimeout(final boolean abandonOnTimeout) {
        this.abandonOnTimeout = abandonOnTimeout;
    }



    public boolean useKeepAlive() {
        return useKeepAlive;
    }



    public void setUseKeepAlive(final boolean useKeepAlive) {
        this.useKeepAlive = useKeepAlive;
    }



    public boolean useLinger() {
        return useLinger;
    }



    public int getLingerTimeoutSeconds() {
        return lingerTimeout;
    }



    public void setUseLinger(final boolean useLinger, final int lingerTimeout) {
        this.useLinger = useLinger;
        this.lingerTimeout = lingerTimeout;
    }



    public boolean useReuseAddress() {
        return useReuseAddress;
    }



    public void setUseReuseAddress(final boolean useReuseAddress) {
        this.useReuseAddress = useReuseAddress;
    }



    public boolean useSchema() {
        return useSchema;
    }


    public void setUseSchema(final boolean useSchema) {
        this.useSchema = useSchema;
        if (useSchema) {
            usePooledSchema = false;
        }
    }


    public boolean usePooledSchema() {
        return usePooledSchema;
    }



    public void setUsePooledSchema(final boolean usePooledSchema) {
        this.usePooledSchema = usePooledSchema;
        if (usePooledSchema) {
            useSchema = false;
        }
    }



    public long getPooledSchemaTimeoutMillis() {
        return pooledSchemaTimeout;
    }


    public void setPooledSchemaTimeoutMillis(final long pooledSchemaTimeout) {
        if (pooledSchemaTimeout < 0) {
            this.pooledSchemaTimeout = 0L;
        } else {
            this.pooledSchemaTimeout = pooledSchemaTimeout;
        }
    }



    public boolean useSynchronousMode() {
        return useSynchronousMode;
    }



    public void setUseSynchronousMode(final boolean useSynchronousMode) {
        this.useSynchronousMode = useSynchronousMode;
    }

    public boolean useTCPNoDelay() {
        return useTCPNoDelay;
    }


    public void setUseTCPNoDelay(final boolean useTCPNoDelay) {
        this.useTCPNoDelay = useTCPNoDelay;
    }


    public boolean followReferrals() {
        return followReferrals;
    }


    public void setFollowReferrals(final boolean followReferrals) {
        this.followReferrals = followReferrals;
    }


    public int getReferralHopLimit() {
        return referralHopLimit;
    }


    public void setReferralHopLimit(final int referralHopLimit) {
        ensureTrue(referralHopLimit > 0,
                "LDAPConnectionOptions.referralHopLimit must be greater than 0.");

        this.referralHopLimit = referralHopLimit;
    }



    public ReferralConnector getReferralConnector() {
        return referralConnector;
    }



    public void setReferralConnector(final ReferralConnector referralConnector) {
        this.referralConnector = referralConnector;
    }



    public int getMaxMessageSize() {
        return maxMessageSize;
    }



    public void setMaxMessageSize(final int maxMessageSize) {
        if (maxMessageSize > 0) {
            this.maxMessageSize = maxMessageSize;
        } else {
            this.maxMessageSize = 0;
        }
    }



    public DisconnectHandler getDisconnectHandler() {
        return disconnectHandler;
    }


    public void setDisconnectHandler(final DisconnectHandler handler) {
        disconnectHandler = handler;
    }


    public UnsolicitedNotificationHandler getUnsolicitedNotificationHandler() {
        return unsolicitedNotificationHandler;
    }



    public void setUnsolicitedNotificationHandler(
            final UnsolicitedNotificationHandler handler) {
        unsolicitedNotificationHandler = handler;
    }


    public int getReceiveBufferSize() {
        return receiveBufferSize;
    }


    public void setReceiveBufferSize(final int receiveBufferSize) {
        if (receiveBufferSize < 0) {
            this.receiveBufferSize = 0;
        } else {
            this.receiveBufferSize = receiveBufferSize;
        }
    }



    public int getSendBufferSize() {
        return sendBufferSize;
    }


    public void setSendBufferSize(final int sendBufferSize) {
        if (sendBufferSize < 0) {
            this.sendBufferSize = 0;
        } else {
            this.sendBufferSize = sendBufferSize;
        }
    }



    public boolean allowConcurrentSocketFactoryUse() {
        return allowConcurrentSocketFactoryUse;
    }


    public void setAllowConcurrentSocketFactoryUse(
            final boolean allowConcurrentSocketFactoryUse) {
        this.allowConcurrentSocketFactoryUse = allowConcurrentSocketFactoryUse;
    }


    @Override()
    public String toString() {
        final StringBuilder buffer = new StringBuilder();
        toString(buffer);
        return buffer.toString();
    }


    public void toString(final StringBuilder buffer) {
        buffer.append("LDAPConnectionOptions(autoReconnect=");
        buffer.append(autoReconnect);
        buffer.append(", bindWithDNRequiresPassword=");
        buffer.append(bindWithDNRequiresPassword);
        buffer.append(", followReferrals=");
        buffer.append(followReferrals);
        if (followReferrals) {
            buffer.append(", referralHopLimit=");
            buffer.append(referralHopLimit);
        }
        if (referralConnector != null) {
            buffer.append(", referralConnectorClass=");
            buffer.append(referralConnector.getClass().getName());
        }
        buffer.append(", useKeepAlive=");
        buffer.append(useKeepAlive);
        buffer.append(", useLinger=");
        if (useLinger) {
            buffer.append("true, lingerTimeoutSeconds=");
            buffer.append(lingerTimeout);
        } else {
            buffer.append("false");
        }
        buffer.append(", useReuseAddress=");
        buffer.append(useReuseAddress);
        buffer.append(", useSchema=");
        buffer.append(useSchema);
        buffer.append(", usePooledSchema=");
        buffer.append(usePooledSchema);
        buffer.append(", pooledSchemaTimeoutMillis=");
        buffer.append(pooledSchemaTimeout);
        buffer.append(", useSynchronousMode=");
        buffer.append(useSynchronousMode);
        buffer.append(", useTCPNoDelay=");
        buffer.append(useTCPNoDelay);
        buffer.append(", captureConnectStackTrace=");
        buffer.append(captureConnectStackTrace);
        buffer.append(", connectTimeoutMillis=");
        buffer.append(connectTimeout);
        buffer.append(", responseTimeoutMillis=");
        buffer.append(responseTimeout);
        buffer.append(", abandonOnTimeout=");
        buffer.append(abandonOnTimeout);
        buffer.append(", maxMessageSize=");
        buffer.append(maxMessageSize);
        buffer.append(", receiveBufferSize=");
        buffer.append(receiveBufferSize);
        buffer.append(", sendBufferSize=");
        buffer.append(sendBufferSize);
        buffer.append(", allowConcurrentSocketFactoryUse=");
        buffer.append(allowConcurrentSocketFactoryUse);
        if (disconnectHandler != null) {
            buffer.append(", disconnectHandlerClass=");
            buffer.append(disconnectHandler.getClass().getName());
        }
        if (unsolicitedNotificationHandler != null) {
            buffer.append(", unsolicitedNotificationHandlerClass=");
            buffer.append(unsolicitedNotificationHandler.getClass().getName());
        }
        buffer.append(')');
    }
}
