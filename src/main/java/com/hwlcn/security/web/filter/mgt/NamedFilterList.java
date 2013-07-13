package com.hwlcn.security.web.filter.mgt;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.List;

public interface NamedFilterList extends List<Filter> {

    String getName();

    FilterChain proxy(FilterChain filterChain);
}
