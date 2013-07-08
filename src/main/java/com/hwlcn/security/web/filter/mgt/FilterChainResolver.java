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
package com.hwlcn.security.web.filter.mgt;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public interface FilterChainResolver {

    /**
     * 根据过滤器 实现对过滤器的拦截处理，对过滤器进行包装扩展
     *
     * @param request       the incoming ServletRequest
     * @param response      the outgoing ServletResponse
     * @param originalChain the original {@code FilterChain} intercepted by the SecurityFilter implementation.
     * @return the filter chain that should be executed for the given request, or {@code null} if the
     *         original chain should be used.
     */
    FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain);

}
