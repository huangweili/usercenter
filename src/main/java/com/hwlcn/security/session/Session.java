/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.hwlcn.security.session;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

/**
 * A {@code Session} is a stateful data context associated with a single Subject (user, daemon process,
 * etc) who interacts with a software system over a period of time.
 * <p/>
 * A {@code Session} is intended to be managed by the business tier and accessible via other
 * tiers without being tied to any given client technology.  This is a <em>great</em> benefit to Java
 * systems, since until now, the only viable session mechanisms were the
 * {@code javax.servlet.http.HttpSession} or Stateful Session EJB's, which many times
 * unnecessarily coupled applications to web or ejb technologies.
 *
 * @since 0.1
 */
public interface Session {


    Serializable getId();

    Date getStartTimestamp();

    Date getLastAccessTime();

    long getTimeout() throws InvalidSessionException;

    void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException;

    String getHost();

    void touch() throws InvalidSessionException;

    void stop() throws InvalidSessionException;

    Collection<Object> getAttributeKeys() throws InvalidSessionException;

    Object getAttribute(Object key) throws InvalidSessionException;

    void setAttribute(Object key, Object value) throws InvalidSessionException;

    Object removeAttribute(Object key) throws InvalidSessionException;
}
