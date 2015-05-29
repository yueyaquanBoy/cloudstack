// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.cloudstack.saml;

import org.apache.cloudstack.api.auth.PluggableAPIAuthenticator;
import org.apache.cloudstack.framework.config.ConfigKey;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public interface SAML2AuthManager extends PluggableAPIAuthenticator {

    public static final ConfigKey<Boolean> SAMLIsPluginEnabled = new ConfigKey<Boolean>("Advanced", Boolean.class, "saml2.enabled", "false",
            "Indicates whether SAML SSO plugin is enabled or not", true);

    public static final ConfigKey<String> SAMLUserAttributeName = new ConfigKey<String>("Advanced", String.class, "saml2.user.attribute", "uid",
            "Attribute name to be looked for in SAML response that will contain the username", true);

    public static final ConfigKey<String> SAMLDefaultDomain = new ConfigKey<String>("Advanced", String.class, "saml2.default.domainid", "1",
            "The default domain UUID to use if domain information is not found while authenticating users", true);

    public static final ConfigKey<String> SAMLCloudStackRedirectionUrl = new ConfigKey<String>("Advanced", String.class, "saml2.redirect.url", "http://localhost:8080/client",
            "The CloudStack UI url the SSO should redirected to when successful", true);

    public static final ConfigKey<String> SAMLServiceProviderSingleSignOnURL = new ConfigKey<String>("Advanced", String.class, "saml2.sp.sso.url", "http://localhost:8080/client/api?command=samlSso",
            "SAML2 CloudStack Service Provider Single Sign On URL", true);

    public static final ConfigKey<String> SAMLServiceProviderSingleLogOutURL = new ConfigKey<String>("Advanced", String.class, "saml2.sp.slo.url", "http://localhost:8080/client/api?command=samlSlo",
            "SAML2 CloudStack Service Provider Single Log Out URL", true);

    public static final ConfigKey<String> SAMLServiceProviderID = new ConfigKey<String>("Advanced", String.class, "saml2.sp.id", "org.apache.cloudstack",
            "SAML2 Service Provider Identifier String", true);

    public static final ConfigKey<String> SAMLIdentityProviderMetadataURL = new ConfigKey<String>("Advanced", String.class, "saml2.idp.metadata.url", "https://openidp.feide.no/simplesaml/saml2/idp/metadata.php",
            "SAML2 Identity Provider Metadata XML Url", true);

    public static final ConfigKey<String> SAMLIdentityProviderId = new ConfigKey<String>("Advanced", String.class, "saml2.idp.id", "https://openidp.feide.no",
            "SAML2 Identity Provider Metadata XML Url", true);

    public static final ConfigKey<Integer> SAMLTimeout = new ConfigKey<Integer>("Advanced", Integer.class, "saml2.timeout", "30000",
            "SAML2 IDP Metadata Downloading and parsing etc. activity timeout in milliseconds", true);

    public String getServiceProviderId();
    public String getIdentityProviderId();

    public X509Certificate getIdpSigningKey();
    public X509Certificate getIdpEncryptionKey();
    public X509Certificate getSpX509Certificate();
    public KeyPair getSpKeyPair();

    public String getSpSingleSignOnUrl();
    public String getIdpSingleSignOnUrl();

    public String getSpSingleLogOutUrl();
    public String getIdpSingleLogOutUrl();
}
