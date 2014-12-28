/**
 * Copyright 2014 (c) Eugene Khrustalev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ru.efo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * {@link org.springframework.security.core.userdetails.UserDetails} implementation used by
 * {@link ADUserDetailsService}
 *
 * @author <a href="mailto:eugene.khrustalev@gmail.com">Eugene Khrustalev</a>
 */
public class ADUserDetails implements UserDetails {

    private final String username;
    private final String password;
    private final String displayName;
    private final String email;
    private final String phone;
    private final boolean blocked;
    private final Set<String> groups;
    private final Set<String> roles;

    public ADUserDetails(String username, String password, String displayName, String email, String phone, boolean blocked, final Set<String> groups, final Set<String> roles) {
        this.username = username;
        this.password = password;
        this.displayName = displayName;
        this.email = email;
        this.phone = phone;
        this.blocked = blocked;
        this.groups = Collections.unmodifiableSet(groups);
        this.roles = Collections.unmodifiableSet(roles);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        final Set<GrantedAuthority> authorities = new HashSet<>();
        for (String role : roles) authorities.add(new SimpleGrantedAuthority(role));
        return authorities;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getUsername() {
        return username;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAccountNonExpired() {
        return !blocked;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAccountNonLocked() {
        return !blocked;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return !blocked;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEnabled() {
        return !blocked;
    }

    /**
     * @return the user's display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * @return the user's e-mail
     */
    public String getEmail() {
        return email;
    }

    /**
     * @return the user's phone
     */
    public String getPhone() {
        return phone;
    }

    /**
     * @return <code>true</code> if user's account is blocked
     */
    public boolean isBlocked() {
        return blocked;
    }

    /**
     * @return the immutable {@link java.util.Set} of roles within the user is member
     */
    public Set<String> getRoles() {
        return roles;
    }

    /**
     * @return the immutable {@link java.util.Set} of AD groups within the user is member
     */
    public Set<String> getGroups() {
        return groups;
    }
}
