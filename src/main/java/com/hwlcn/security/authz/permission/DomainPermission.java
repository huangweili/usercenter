package com.hwlcn.security.authz.permission;

import com.hwlcn.security.util.StringUtils;

import java.util.Set;


public class DomainPermission extends WildcardPermission {

    private String domain;
    private Set<String> actions;
    private Set<String> targets;

    private static final long serialVersionUID = 1l;

    public DomainPermission() {
        this.domain = getDomain(getClass());
        setParts(getDomain(getClass()));
    }

    public DomainPermission(String actions) {
        domain = getDomain(getClass());
        this.actions = StringUtils.splitToSet(actions, SUBPART_DIVIDER_TOKEN);
        encodeParts(domain, actions, null);
    }

    public DomainPermission(String actions, String targets) {
        this.domain = getDomain(getClass());
        this.actions = StringUtils.splitToSet(actions, SUBPART_DIVIDER_TOKEN);
        this.targets = StringUtils.splitToSet(targets, SUBPART_DIVIDER_TOKEN);
        encodeParts(this.domain, actions, targets);
    }

    protected DomainPermission(Set<String> actions, Set<String> targets) {
        this.domain = getDomain(getClass());
        setParts(domain, actions, targets);
    }

    private void encodeParts(String domain, String actions, String targets) {
        if (!StringUtils.hasText(domain)) {
            throw new IllegalArgumentException("domain argument cannot be null or empty.");
        }
        StringBuilder sb = new StringBuilder(domain);

        if (!StringUtils.hasText(actions)) {
            if (StringUtils.hasText(targets)) {
                sb.append(PART_DIVIDER_TOKEN).append(WILDCARD_TOKEN);
            }
        } else {
            sb.append(PART_DIVIDER_TOKEN).append(actions);
        }
        if (StringUtils.hasText(targets)) {
            sb.append(PART_DIVIDER_TOKEN).append(targets);
        }
        setParts(sb.toString());
    }

    protected void setParts(String domain, Set<String> actions, Set<String> targets) {
        String actionsString = StringUtils.toDelimitedString(actions, SUBPART_DIVIDER_TOKEN);
        String targetsString = StringUtils.toDelimitedString(targets, SUBPART_DIVIDER_TOKEN);
        encodeParts(domain, actionsString, targetsString);
        this.domain = domain;
        this.actions = actions;
        this.targets = targets;
    }

    protected String getDomain(Class<? extends DomainPermission> clazz) {
        String domain = clazz.getSimpleName().toLowerCase();
        //strip any trailing 'permission' text from the name (as all subclasses should have been named):
        int index = domain.lastIndexOf("permission");
        if (index != -1) {
            domain = domain.substring(0, index);
        }
        return domain;
    }

    public String getDomain() {
        return domain;
    }

    protected void setDomain(String domain) {
        if (this.domain != null && this.domain.equals(domain)) {
            return;
        }
        this.domain = domain;
        setParts(domain, actions, targets);
    }

    public Set<String> getActions() {
        return actions;
    }

    protected void setActions(Set<String> actions) {
        if (this.actions != null && this.actions.equals(actions)) {
            return;
        }
        this.actions = actions;
        setParts(domain, actions, targets);
    }

    public Set<String> getTargets() {
        return targets;
    }

    protected void setTargets(Set<String> targets) {
        this.targets = targets;
        if (this.targets != null && this.targets.equals(targets)) {
            return;
        }
        this.targets = targets;
        setParts(domain, actions, targets);
    }
}
