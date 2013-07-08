package com.hwlcn.security.web.filter.mgt;

import com.hwlcn.security.config.ConfigurationException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.Map;
import java.util.Set;

public interface FilterChainManager {

    Map<String, Filter> getFilters();

    NamedFilterList getChain(String chainName);

    boolean hasChains();

    Set<String> getChainNames();

    FilterChain proxy(FilterChain original, String chainName);

    void addFilter(String name, Filter filter);

    void addFilter(String name, Filter filter, boolean init);

    void createChain(String chainName, String chainDefinition);

    void addToChain(String chainName, String filterName);

    void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) throws ConfigurationException;
}
