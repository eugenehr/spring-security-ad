## spring-security-ad

A Microsoft Active Directory based AuthenticationProvider and UserDetailsService for [Spring Security](http://projects.spring.io/spring-security/).

It works with Windows 2003, 2008 and 2012 servers.

### Project setup

**pom.xml**

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-context</artifactId>
        <version>${spring.version}</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-config</artifactId>
        <version>${spring.security.version}</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-web</artifactId>
        <version>${spring.security.version}</version>
    </dependency>
    <dependency>
        <groupId>ru.efo.security</groupId>
        <artifactId>spring-security-ad</artifactId>
        <version>${spring.security.ad.version}</version>
    </dependency>
</dependencies>
```

**applicationContext.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans:beans xmlns:security="http://www.springframework.org/schema/security"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xmlns:p="http://www.springframework.org/schema/p"
             xmlns:util="http://www.springframework.org/schema/util"
             xmlns:beans="http://www.springframework.org/schema/beans"
             xsi:schemaLocation="http://www.springframework.org/schema/security
                                 http://www.springframework.org/schema/security/spring-security-3.2.xsd
                                 http://www.springframework.org/schema/util
                                 http://www.springframework.org/schema/util/spring-util.xsd
                                 http://www.springframework.org/schema/beans
                                 http://www.springframework.org/schema/beans/spring-beans.xsd">

    <util:map id="rolesMapping">
        <!-- Domain Admins and Backup Operators from Active Directory will have 'ROLE_ADMIN' application role-->
        <beans:entry key="ROLE_ADMIN" value="Domain Admins|Backup Operators"/>
        <!-- Any authenticated user will have 'ROLE_USER' application role -->
        <beans:entry key="ROLE_USER" value=".+"/>
    </util:map>

    <beans:bean id="userDetailsService" class="ru.efo.security.ADUserDetailsService"
                p:ldapUrl="ldap://dc.example.com:389"
                p:rolesMapping-ref="rolesMapping"/>

    <security:global-method-security secured-annotations="enabled"/>

    <security:authentication-manager alias="authenticationManager">
        <!-- Using as Authentication Provider -->
        <security:authentication-provider ref="userDetailsService"/>
        <!-- Using as UserDetailsService -->
        <security:authentication-provider user-details-service-ref="userDetailsService"/>
    </security:authentication-manager>

    <security:http>
        <security:intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <!-- All authenticated users can access to any application url -->
        <security:intercept-url pattern="/**" access="ROLE_USER"/>
        <!-- Only Domain Admins and Backup Operators can access to /admin url -->
        <security:intercept-url pattern="/admin/**" access="ROLE_ADMIN"/>

        <security:form-login login-page="/login.html"
                             username-parameter="username"
                             password-parameter="password"
                             login-processing-url="/dologin"/>
        <security:logout logout-url="/logout.html" invalidate-session="true"/>
    </security:http>
</beans:beans>
```

### Properties

Property             | Used with          | Description
---------------------|--------------------|---------------
ldapUrl              | Both               | A Domain Controller url. <br/> Example: **ldap://dc.example.com:389**
ldapAccount          | UserDetailsService | An Active Directory account to discover information about users and their groups.
ldapPassword         | UserDetailsService | A password for **ldapAccount** property.
userSearchBase       | Both               | A base DN to search users. <br/> Example: **dc=example,dc=com**
groupSearchBase      | Both               | A base DN to search group. If not set then **userSearchBase** will used instead.
userSuffix           | Both               | A user suffix. If not set then it will be determined from **userSearchBase** property:<br/> Example: <br/> if **userSearchBase** property is **"cn=Users,dc=example,dc=com"** then **userSuffix** will be **"@example.com"**. **CN** is ignored.
recursiveRoleSearch  | Both               | If set then roles will be descovered recursively. <br/> Example: <br/> if user is member of **Managers** group and **Managers** is member of **Sales** group then user is member of **Sales** group too. <br/> Default is **true**.
rolePrefix           | Both               | A prefix that attached to Active Directory groups. Used if property **rolesMapping** is not set. Default is **"ROLE_"**. <br/> For example: <br/> **Domain Users** => **ROLE_DOMAIN_USERS** <br/> **Sales** => **ROLE_SALES**. All spaces will be replaced to **'_'** and others characters will be uppercased.
rolesMapping         | Both               | If set then is used instead of **rolePrefix** property. <br/> Every **key** in that map is interpreted as an **application role** and **values** are regular expressions that are applied to Active Directory groups. <br/> Example: <br/> 1. **"ROLE_ADMIN"** => **"Domain Admins&#124;Backup Operators"** <br/>**Domain Admins** and **Backup Operators** will have **ROLE_ADMIN** application role <br/> 2. **"ROLE_USER"** => **".+"** <br/>All authenticated users will have **ROLE_USER** application role


### Licensing Mumbo Jumbo

This software is licensed under the [Apache License, Version 2.0 ](http://www.apache.org/licenses/LICENSE-2.0).
