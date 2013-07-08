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
package com.hwlcn.security.mgt;

import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.support.DelegatingSubject;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.SubjectContext;


/**
 * Default {@link SubjectFactory SubjectFactory} implementation that creates {@link com.hwlcn.security.subject.support.DelegatingSubject DelegatingSubject}
 * instances.
 *
 * @since 1.0
 */
public class DefaultSubjectFactory implements SubjectFactory {

    public DefaultSubjectFactory() {
    }

    public Subject createSubject(SubjectContext context) {
        SecurityManager securityManager = context.resolveSecurityManager();
        Session session = context.resolveSession();
        boolean sessionCreationEnabled = context.isSessionCreationEnabled();
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();
        String host = context.resolveHost();

        return new DelegatingSubject(principals, authenticated, host, session, sessionCreationEnabled, securityManager);
    }

    /**
     * @deprecated since 1.2 - override {@link #createSubject(com.hwlcn.security.subject.SubjectContext)} directly if you
     *             need to instantiate a custom {@link Subject} class.
     */
    @Deprecated
    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated, String host,
                                         Session session, SecurityManager securityManager) {
        return new DelegatingSubject(principals, authenticated, host, session, true, securityManager);
    }

}
