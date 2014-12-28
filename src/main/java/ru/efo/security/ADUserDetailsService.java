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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link org.springframework.security.core.userdetails.UserDetailsService} implementation for Spring Security
 * to provide authentication with Microsoft Active Directory
 *
 * @author <a href="mailto:eugene.khrustalev@gmail.com">Eugene Khrustalev</a>
 */
public class ADUserDetailsService implements UserDetailsService, AuthenticationProvider {

    private static final Logger logger = Logger.getLogger(ADUserDetailsService.class.getName());

    private String ldapUrl;
    private String ldapAccount;
    private String ldapPassword;
    private String userSearchBase;
    private String groupSearchBase;
    private String userSuffix;
    private boolean recursiveRoleSearch = true;
    private Map<String, String> rolesMapping = null;
    private String rolePrefix = "ROLE_";
    private String displayNameAttribute = "displayName";
    private String emailAttribute = "mail";
    private String phoneAttribute = "telephoneNumber";

    /**
     * @return the connection url to the Domain Controller
     */
    public String getLdapUrl() {
        return ldapUrl;
    }

    /**
     * Set the connection url to the Active Directory Domain Controller.
     * For example: <code>ldap://dc1.example.com:389</code>
     *
     * @param ldapUrl the connection url
     */
    public void setLdapUrl(String ldapUrl) {
        this.ldapUrl = ldapUrl;
    }

    /**
     * @return the Active Directory account to discovering user information and groups
     */
    public String getLdapAccount() {
        return ldapAccount;
    }

    /**
     * Set the Active Directory account to discovering user information and groups
     *
     * @param ldapAccount the account
     */
    public void setLdapAccount(String ldapAccount) {
        this.ldapAccount = ldapAccount;
    }

    /**
     * @return password for {@link #getLdapAccount()}
     */
    public String getLdapPassword() {
        return ldapPassword;
    }

    /**
     * Set the password for  {@link #getLdapAccount()}
     *
     * @param ldapPassword the password
     */
    public void setLdapPassword(String ldapPassword) {
        this.ldapPassword = ldapPassword;
    }

    /**
     * @return the base DN to search user accounts
     */
    public String getUserSearchBase() {
        return userSearchBase;
    }

    /**
     * Set the base DN to search users accounts.
     * For example: <code>dc=example,dc=com</code>
     *
     * @param userSearchBase the DN
     */
    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
        if (userSuffix == null && userSearchBase != null) {
            // If userSuffix is not set then determine it from searchBase
            final Pattern pattern = Pattern.compile("dc\\s*=\\s*(.+)", Pattern.CASE_INSENSITIVE);
            userSuffix = "";
            for (String part : userSearchBase.split(",")) {
                final Matcher matcher = pattern.matcher(part);
                if (matcher.matches()) {
                    userSuffix += (userSuffix.isEmpty() ? "@" : ".") + matcher.group(1);
                }
            }
        }
    }

    /**
     * @return the base DN to search groups
     */
    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    /**
     * Set the base DN to search groups. If not set then {@link #getUserSearchBase()} will be used
     *
     * @param groupSearchBase the DN
     */
    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = groupSearchBase;
    }

    /**
     * @return the suffix is attached to user logins
     */
    public String getUserSuffix() {
        return userSuffix;
    }

    /**
     * Set the suffix is attached to user logins.
     * For example: <code>@example.com</code>
     *
     * @param userSuffix the suffix
     */
    public void setUserSuffix(String userSuffix) {
        this.userSuffix = userSuffix;
    }

    /**
     * @return is recursive group discovering enabled?
     */
    public boolean isRecursiveRoleSearch() {
        return recursiveRoleSearch;
    }

    /**
     * Enable or disable recursive group discovering
     *
     * @param recursiveRoleSearch <code>true</code> for recursive group discovering
     */
    public void setRecursiveRoleSearch(boolean recursiveRoleSearch) {
        this.recursiveRoleSearch = recursiveRoleSearch;
    }

    /**
     * @return the mappings for application roles and Active Directory user groups
     */
    public Map<String, String> getRolesMapping() {
        return rolesMapping;
    }

    /**
     * Set the mappings for application roles and Active Directory user groups.
     * Keys from this map will be interpreted as application roles and values as
     * regular expressions for Active Directory groups.
     * <br/>
     * For example:
     * <pre>
     *      Map&lt;String, String&gt; rolesMappings = new HashMap&lt;&gt;();
     *
     *      // Domain Admins and Backup Operators from Active Directory will have role 'ROLE_ADMIN' in application
     *      rolesMappings.put("ROLE_ADMIN", "Domain Admins|Backup Operators");
     *
     *      // All users will have role 'ROLE_USER' in application
     *      rolesMappings.put("ROLE_USER", ".+");
     * </pre>
     *
     * @param rolesMapping the mappings
     */
    public void setRolesMapping(Map<String, String> rolesMapping) {
        this.rolesMapping = rolesMapping;
    }

    /**
     * @return the prefix for Active Directory groups. Default is <code>ROLE_</code>
     */
    public String getRolePrefix() {
        return rolePrefix;
    }

    /**
     * Set the prefix for Active Directory groups.
     * If application is not used {@link #getRolesMapping()} then every Active Directory group
     * will be set as application role with given prefix. All spaces and '-' characters will also
     * replaced with '_'.
     * <br/>
     * For example (with prefix 'ROLE_'):
     * <pre>
     *     AD Group       |  App Role
     *     -------------------------------------
     *     Domain Admins  |  ROLE_DOMAIN_ADMINS
     *     Domain Users   |  ROLE_DOMAIN_USERS
     * </pre>
     *
     * @param rolePrefix the prefix
     */
    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    /**
     * @return the name of attribute contains user's <code>displayName</code> information
     */
    public String getDisplayNameAttribute() {
        return displayNameAttribute;
    }

    /**
     * Set the name of attribute contains user's <code>displayName</code> information.
     * Default is <code>displayName</code>
     *
     * @param displayNameAttribute the name
     */
    public void setDisplayNameAttribute(String displayNameAttribute) {
        this.displayNameAttribute = displayNameAttribute;
    }

    /**
     * @return the name of attribute contains user's <code>e-mail</code> information
     */
    public String getEmailAttribute() {
        return emailAttribute;
    }

    /**
     * Set the name of attribute contains user's <code>e-mail</code> information.
     * Default is <code>mail</code>
     *
     * @param emailAttribute the name
     */
    public void setEmailAttribute(String emailAttribute) {
        this.emailAttribute = emailAttribute;
    }

    /**
     * @return the name of attribute contains user's <code>phone</code> information
     */
    public String getPhoneAttribute() {
        return phoneAttribute;
    }

    /**
     * Set the name of attribute contains user's <code>phone</code> information.
     * Default is <code>telephoneNumber</code>
     *
     * @param phoneAttribute the name
     */
    public void setPhoneAttribute(String phoneAttribute) {
        this.phoneAttribute = phoneAttribute;
    }

    @Override
    public ADUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DirContext context = null;
        try {
            context = getDirContext(ldapAccount + userSuffix, ldapPassword);
            logger.log(Level.FINE, "Successfully logged on " + ldapUrl);
            return loadUserByUsername(context, username, null);
        } catch (NamingException ex) {
            logger.log(Level.SEVERE, "Could not login to " + ldapUrl, ex);
            throw new UsernameNotFoundException(ex.getMessage());
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException ex) {
                    logger.log(Level.WARNING, "Could not close DirContext", ex);
                }
            }
        }
    }

    private ADUserDetails loadUserByUsername(DirContext context, String username, String password) throws UsernameNotFoundException {
        try {
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            // search for username
            NamingEnumeration<SearchResult> renum = context.search(userSearchBase, "(&(objectClass=user)(sAMAccountName={0}))",
                    new Object[]{username}, controls);
            if (!renum.hasMoreElements()) {
                throw new UsernameNotFoundException("User '" + username + "' is not exist");
            }
            SearchResult result = renum.next();
            final Attributes attributes = result.getAttributes();

            // User's display name
            String displayName = null;
            Attribute attr = attributes.get(displayNameAttribute);
            if (attr != null) {
                displayName = attr.get().toString();
            }
            if (!StringUtils.hasText(displayName)) displayName = username;
            logger.log(Level.FINE, "Display name: " + displayName);

            // User's email
            String email = null;
            attr = attributes.get(emailAttribute);
            if (attr != null) {
                email = attr.get().toString();
            }
            logger.log(Level.FINE, "E-mail: " + email);

            // User's phone number
            String phone = null;
            attr = attributes.get(phoneAttribute);
            if (attr != null) {
                phone = attr.get().toString();
            }
            logger.log(Level.FINE, "Phone: " + phone);

            // Is user blocked
            boolean blocked = false;
            attr = attributes.get("userAccountControl");
            if (attr != null) {
                blocked = (Long.parseLong(attr.get().toString()) & 2) != 0;
            }
            logger.log(Level.FINE, "Blocked: " + blocked);

            // describe roles and groups
            final Set<String> roles = new TreeSet<>();
            final Set<String> groups = new TreeSet<>();
            Attribute memberOf = attributes.get("memberOf");
            describeRoles(context, memberOf, groups, roles);

            // Describe user primary role
            Attribute attrPrimaryGroupId = attributes.get("primaryGroupId");
            Attribute attrObjectSid = attributes.get("objectSid");
            if (attrPrimaryGroupId != null && attrObjectSid != null) {
                int primaryGroupId = Integer.parseInt(attrPrimaryGroupId.get().toString());
                byte[] objectSid = (byte[]) attrObjectSid.get();
                // add primary group RID
                for (int i = 0; i < 4; i++) {
                    objectSid[objectSid.length - 4 + i] = (byte) (primaryGroupId & 0xFF);
                    primaryGroupId >>= 8;
                }
                StringBuilder tmp = new StringBuilder();
                for (int i = 2; i <= 7; i++) {
                    tmp.append(Integer.toHexString(objectSid[i] & 0xFF));
                }
                // convert objectSid to String
                StringBuilder sidBuilder = new StringBuilder("S-").append(objectSid[0]).append("-").append(Long.parseLong(tmp.toString(), 16));
                // the sub authorities count
                int count = objectSid[1];
                // add authorities
                for (int i = 0; i < count; i++) {
                    tmp.setLength(0);

                    int offset = i * 4;
                    tmp.append(String.format("%02X%02X%02X%02X",
                            (objectSid[11 + offset] & 0xFF),
                            (objectSid[10 + offset] & 0xFF),
                            (objectSid[9 + offset] & 0xFF),
                            (objectSid[8 + offset] & 0xFF)));
                    sidBuilder.append('-').append(Long.parseLong(tmp.toString(), 16));
                }
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                renum = context.search(userSearchBase, "(&(objectClass=group)(objectSid={0}))", new Object[]{sidBuilder.toString()}, searchControls);
                if (renum.hasMoreElements()) {
                    result = renum.next();
                    attr = result.getAttributes().get("distinguishedName");
                    describeRoles(context, attr, groups, roles);
                }
            }
            return new ADUserDetails(username, password, displayName, email, phone, blocked, groups, roles);
        } catch (NamingException ex) {
            logger.log(Level.SEVERE, "Could not find user '" + username + "'", ex);
            throw new UsernameNotFoundException(ex.getMessage());
        }
    }

    private DirContext getDirContext(String username, String password) throws NamingException {
        final Properties props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, username);
        props.put(Context.SECURITY_CREDENTIALS, password);
        props.put(Context.PROVIDER_URL, ldapUrl);
        props.put("java.naming.ldap.attributes.binary", "objectSID");

        return new InitialDirContext(props);
    }

    private void describeRoles(DirContext context, Attribute memberOf, Set<String> groups, Set<String> roles) throws NamingException {
        if (memberOf != null) {
            for (int i = 0; i < memberOf.size(); i++) {
                Attribute attr = context.getAttributes(memberOf.get(i).toString(), new String[]{"CN"}).get("CN");
                if (attr != null) {
                    final String role = attr.get().toString();
                    if (rolesMapping != null) {
                        for (String key : rolesMapping.keySet()) {
                            if (role.matches(rolesMapping.get(key))) {
                                if (logger.isLoggable(Level.FINE)) {
                                    if (!roles.contains(key)) {
                                        logger.log(Level.FINE, "Role: " + key);
                                    }
                                }
                                roles.add(key);
                            }
                        }
                    } else {
                        final String roleWithPrefix = (rolePrefix == null ? "" : rolePrefix) +
                                role.toUpperCase().replaceAll("(\\s|-)+", "_");
                        if (logger.isLoggable(Level.FINE)) {
                            if (!roles.contains(role)) {
                                logger.log(Level.FINE, "Role: " + roleWithPrefix);
                            }
                        }
                        roles.add(roleWithPrefix);
                    }
                    groups.add(role);

                    if (recursiveRoleSearch) {
                        SearchControls controls = new SearchControls();
                        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        NamingEnumeration<SearchResult> renum = context.search(
                                groupSearchBase != null ? groupSearchBase : userSearchBase,
                                "(CN=" + role + ")", controls);
                        if (renum.hasMore()) {
                            SearchResult searchResult = renum.next();
                            attr = searchResult.getAttributes().get("memberOf");
                            describeRoles(context, attr, groups, roles);
                        }
                    }
                }
            }
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();
        logger.log(Level.FINE, "Performing logon into '" + ldapUrl + "' with credentials '" + username + "'/'" + password.replaceAll(".", "*") + "'");

        DirContext context = null;
        try {
            context = getDirContext(username + userSuffix, password);
            logger.log(Level.FINE, "User '" + username + "' has been successfully logged on");
            final ADUserDetails details = loadUserByUsername(context, username, password);
            return new UsernamePasswordAuthenticationToken(details, password, details.getAuthorities());
        } catch (NamingException ex) {
            logger.log(Level.SEVERE, "Could not login into '" + ldapUrl + "'", ex);
            throw new BadCredentialsException(ex.getMessage());
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException ex) {
                    logger.log(Level.WARNING, "Could not close DirContext", ex);
                }
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
