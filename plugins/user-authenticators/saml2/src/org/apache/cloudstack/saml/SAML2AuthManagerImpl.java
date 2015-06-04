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

import com.cloud.utils.component.AdapterBase;
import org.apache.cloudstack.api.auth.PluggableAPIAuthenticator;
import org.apache.cloudstack.api.command.GetServiceProviderMetaDataCmd;
import org.apache.cloudstack.api.command.ListIdpsCmd;
import org.apache.cloudstack.api.command.SAML2LoginAPIAuthenticatorCmd;
import org.apache.cloudstack.api.command.SAML2LogoutAPIAuthenticatorCmd;
import org.apache.cloudstack.framework.config.ConfigKey;
import org.apache.cloudstack.framework.config.Configurable;
import org.apache.cloudstack.framework.security.keystore.KeystoreDao;
import org.apache.cloudstack.framework.security.keystore.KeystoreVO;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.springframework.stereotype.Component;

import javax.ejb.Local;
import javax.inject.Inject;
import javax.xml.stream.FactoryConfigurationError;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Local(value = {SAML2AuthManager.class, PluggableAPIAuthenticator.class})
public class SAML2AuthManagerImpl extends AdapterBase implements SAML2AuthManager, Configurable {
    private static final Logger s_logger = Logger.getLogger(SAML2AuthManagerImpl.class);

    private SAMLProviderMetadata _spMetadata = new SAMLProviderMetadata();
    private Map<String, SAMLProviderMetadata> _idpMetadataMap = new HashMap<String, SAMLProviderMetadata>();

    private String idpSingleSignOnUrl;
    private String idpSingleLogOutUrl;

    private HTTPMetadataProvider idpMetaDataProvider;

    @Inject
    private KeystoreDao _ksDao;

    @Override
    public boolean start() {
        if (isSAMLPluginEnabled()) {
            setup();
            s_logger.info("SAML auth plugin loaded");
        } else {
            s_logger.info("SAML auth plugin not enabled so not loading");
        }
        return super.start();
    }

    private boolean initSP() {
        KeystoreVO keyStoreVO = _ksDao.findByName(SAMLPluginConstants.SAMLSP_KEYPAIR);
        if (keyStoreVO == null) {
            try {
                KeyPair keyPair = SAMLUtils.generateRandomKeyPair();
                _ksDao.save(SAMLPluginConstants.SAMLSP_KEYPAIR, SAMLUtils.savePrivateKey(keyPair.getPrivate()), SAMLUtils.savePublicKey(keyPair.getPublic()), "samlsp-keypair");
                keyStoreVO = _ksDao.findByName(SAMLPluginConstants.SAMLSP_KEYPAIR);
                s_logger.info("No SAML keystore found, created and saved a new Service Provider keypair");
            } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
                s_logger.error("Unable to create and save SAML keypair: " + e.toString());
            }
        }

        String spId = SAMLServiceProviderID.value();
        String spSsoUrl = SAMLServiceProviderSingleSignOnURL.value();
        String spSloUrl = SAMLServiceProviderSingleLogOutURL.value();
        String spOrgName = SAMLServiceProviderOrgName.value();
        String spOrgUrl = SAMLServiceProviderOrgUrl.value();
        String spContactPersonName = SAMLServiceProviderContactPersonName.value();
        String spContactPersonEmail = SAMLServiceProviderContactEmail.value();
        KeyPair spKeyPair = null;
        X509Certificate spX509Key = null;
        if (keyStoreVO != null) {
            PrivateKey privateKey = SAMLUtils.loadPrivateKey(keyStoreVO.getCertificate());
            PublicKey publicKey = SAMLUtils.loadPublicKey(keyStoreVO.getKey());
            if (privateKey != null && publicKey != null) {
                spKeyPair = new KeyPair(publicKey, privateKey);
                KeystoreVO x509VO = _ksDao.findByName(SAMLPluginConstants.SAMLSP_X509CERT);
                if (x509VO == null) {
                    try {
                        spX509Key = SAMLUtils.generateRandomX509Certificate(spKeyPair);
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        ObjectOutput out = new ObjectOutputStream(bos);
                        out.writeObject(spX509Key);
                        out.flush();
                        _ksDao.save(SAMLPluginConstants.SAMLSP_X509CERT, Base64.encodeBase64String(bos.toByteArray()), "", "samlsp-x509cert");
                        bos.close();
                    } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateEncodingException | SignatureException | InvalidKeyException | IOException e) {
                        s_logger.error("SAML Plugin won't be able to use X509 signed authentication");
                    }
                } else {
                    try {
                        ByteArrayInputStream bi = new ByteArrayInputStream(Base64.decodeBase64(x509VO.getCertificate()));
                        ObjectInputStream si = new ObjectInputStream(bi);
                        spX509Key = (X509Certificate) si.readObject();
                        bi.close();
                    } catch (IOException | ClassNotFoundException ignored) {
                        s_logger.error("SAML Plugin won't be able to use X509 signed authentication. Failed to load X509 Certificate from Database.");
                    }
                }
            }
        }
        if (spKeyPair != null && spX509Key != null
                && spId != null && spSsoUrl != null && spSloUrl != null
                && spOrgName != null && spOrgUrl != null
                && spContactPersonName != null && spContactPersonEmail != null) {
            _spMetadata.setEntityId(spId);
            _spMetadata.setOrganizationName(spOrgName);
            _spMetadata.setOrganizationUrl(spOrgUrl);
            _spMetadata.setContactPersonName(spContactPersonName);
            _spMetadata.setContactPersonEmail(spContactPersonEmail);
            _spMetadata.setSsoUrl(spSsoUrl);
            _spMetadata.setSloUrl(spSloUrl);
            _spMetadata.setKeyPair(spKeyPair);
            _spMetadata.setSigningCertificate(spX509Key);
            _spMetadata.setEncryptionCertificate(spX509Key);
            return true;
        }
        return false;
    }

    private void addIdpToMap(EntityDescriptor descriptor, Map<String, SAMLProviderMetadata> idpMap) {
        SAMLProviderMetadata idpMetadata = new SAMLProviderMetadata();
        idpMetadata.setEntityId(descriptor.getEntityID());
        s_logger.debug("Adding IdP to the list of discovered IdPs: " + descriptor.getEntityID());
        if (descriptor.getOrganization() != null) {
            if (descriptor.getOrganization().getDisplayNames() != null) {
                for (OrganizationDisplayName orgName : descriptor.getOrganization().getDisplayNames()) {
                    if (orgName != null && orgName.getName() != null) {
                        idpMetadata.setOrganizationName(orgName.getName().getLocalString());
                        break;
                    }
                }
            }
            if (idpMetadata.getOrganizationName() == null && descriptor.getOrganization().getOrganizationNames() != null) {
                for (OrganizationName orgName : descriptor.getOrganization().getOrganizationNames()) {
                    if (orgName != null && orgName.getName() != null) {
                        idpMetadata.setOrganizationName(orgName.getName().getLocalString());
                        break;
                    }
                }
            }
            if (descriptor.getOrganization().getURLs() != null) {
                for (OrganizationURL organizationURL : descriptor.getOrganization().getURLs()) {
                    if (organizationURL != null && organizationURL.getURL() != null) {
                        idpMetadata.setOrganizationUrl(organizationURL.getURL().getLocalString());
                        break;
                    }
                }
            }
        }
        if (descriptor.getContactPersons() != null) {
            for (ContactPerson person : descriptor.getContactPersons()) {
                if (person == null || (person.getGivenName() == null && person.getSurName() == null)
                        || person.getEmailAddresses() == null) {
                    continue;
                }
                if (person.getGivenName() != null) {
                    idpMetadata.setContactPersonName(person.getGivenName().getName());

                } else if (person.getSurName() != null) {
                    idpMetadata.setContactPersonName(person.getSurName().getName());
                }
                for (EmailAddress emailAddress : person.getEmailAddresses()) {
                    if (emailAddress != null && emailAddress.getAddress() != null) {
                        idpMetadata.setContactPersonEmail(emailAddress.getAddress());
                    }
                }
                if (idpMetadata.getContactPersonName() != null && idpMetadata.getContactPersonEmail() != null) {
                    break;
                }
            }
        }

        IDPSSODescriptor idpDescriptor = descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (idpDescriptor != null) {
            if (idpDescriptor.getSingleSignOnServices() != null) {
                for (SingleSignOnService ssos : idpDescriptor.getSingleSignOnServices()) {
                    if (ssos.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                        idpMetadata.setSsoUrl(ssos.getLocation());
                    }
                }
            }
            if (idpDescriptor.getSingleLogoutServices() != null) {
                for (SingleLogoutService slos : idpDescriptor.getSingleLogoutServices()) {
                    if (slos.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                        idpMetadata.setSloUrl(slos.getLocation());
                    }
                }
            }

            X509Certificate unspecifiedKey = null;
            if (idpDescriptor.getKeyDescriptors() != null) {
                for (KeyDescriptor kd : idpDescriptor.getKeyDescriptors()) {
                    if (kd.getUse() == UsageType.SIGNING) {
                        try {
                            idpMetadata.setSigningCertificate(KeyInfoHelper.getCertificates(kd.getKeyInfo()).get(0));
                        } catch (CertificateException ignored) {
                        }
                    }
                    if (kd.getUse() == UsageType.ENCRYPTION) {
                        try {
                            idpMetadata.setEncryptionCertificate(KeyInfoHelper.getCertificates(kd.getKeyInfo()).get(0));
                        } catch (CertificateException ignored) {
                        }
                    }
                    if (kd.getUse() == UsageType.UNSPECIFIED) {
                        try {
                            unspecifiedKey = KeyInfoHelper.getCertificates(kd.getKeyInfo()).get(0);
                        } catch (CertificateException ignored) {
                        }
                    }
                }
            }
            if (idpMetadata.getSigningCertificate() == null && unspecifiedKey != null) {
                idpMetadata.setSigningCertificate(unspecifiedKey);
            }
            if (idpMetadata.getEncryptionCertificate() == null && unspecifiedKey != null) {
                idpMetadata.setEncryptionCertificate(unspecifiedKey);
            }
            if (idpMap.containsKey(idpMetadata.getEntityId())) {
                s_logger.warn("Duplicate IdP metadata found with entity Id: " + idpMetadata.getEntityId());
            }
            idpMap.put(idpMetadata.getEntityId(), idpMetadata);
        }
    }

    private void discoverAndAddIdp(XMLObject metadata, Map<String, SAMLProviderMetadata> idpMap) {
        if (metadata instanceof EntityDescriptor) {
            EntityDescriptor entityDescriptor = (EntityDescriptor) metadata;
            addIdpToMap(entityDescriptor, idpMap);
        } else if (metadata instanceof EntitiesDescriptor) {
            EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) metadata;
            if (entitiesDescriptor.getEntityDescriptors() != null) {
                for (EntityDescriptor entityDescriptor: entitiesDescriptor.getEntityDescriptors()) {
                    addIdpToMap(entityDescriptor, idpMap);
                }
            }
            if (entitiesDescriptor.getEntitiesDescriptors() != null) {
                for (EntitiesDescriptor entitiesDescriptorInner: entitiesDescriptor.getEntitiesDescriptors()) {
                    discoverAndAddIdp(entitiesDescriptorInner, idpMap);
                }
            }
        }
    }

    private boolean setup() {
        if (!initSP()) {
            s_logger.error("SAML Plugin failed to initialize, please fix the configuration and restart management server");
            return false;
        }
        String idpMetaDataUrl = SAMLIdentityProviderMetadataURL.value();
        int tolerance = 30000;
        tolerance = SAMLTimeout.value();
        try {
            DefaultBootstrap.bootstrap();
            idpMetaDataProvider = new HTTPMetadataProvider(idpMetaDataUrl, tolerance);
            idpMetaDataProvider.setRequireValidMetadata(true);
            idpMetaDataProvider.setParserPool(new BasicParserPool());
            idpMetaDataProvider.initialize();
            _idpMetadataMap.clear();
            discoverAndAddIdp(idpMetaDataProvider.getMetadata(), _idpMetadataMap);
        } catch (MetadataProviderException e) {
            s_logger.error("Unable to read SAML2 IDP MetaData URL, error:" + e.getMessage());
            s_logger.error("SAML2 Authentication may be unavailable");
        } catch (ConfigurationException | FactoryConfigurationError e) {
            s_logger.error("OpenSAML bootstrapping failed: error: " + e.getMessage());
        } catch (NullPointerException e) {
            s_logger.error("Unable to setup SAML Auth Plugin due to NullPointerException" +
                    " please check the SAML IDP metadata URL and entity ID in global settings: " + e.getMessage());
        }
        return true;
    }

    @Override
    public List<Class<?>> getAuthCommands() {
        List<Class<?>> cmdList = new ArrayList<Class<?>>();
        if (!isSAMLPluginEnabled()) {
            return cmdList;
        }
        cmdList.add(SAML2LoginAPIAuthenticatorCmd.class);
        cmdList.add(SAML2LogoutAPIAuthenticatorCmd.class);
        cmdList.add(GetServiceProviderMetaDataCmd.class);
        cmdList.add(ListIdpsCmd.class);
        return cmdList;
    }

    @Override
    public SAMLProviderMetadata getSPMetadata() {
        return _spMetadata;
    }

    @Override
    public SAMLProviderMetadata getIdPMetadata(String entityId) {
        if (entityId != null && _idpMetadataMap.containsKey(entityId)) {
            return _idpMetadataMap.get(entityId);
        }
        String defaultIdpId = SAMLDefaultIdentityProviderId.value();
        if (defaultIdpId != null && _idpMetadataMap.containsKey(defaultIdpId)) {
            return _idpMetadataMap.get(defaultIdpId);
        }
        // In case of a single IdP, return that as default
        if (_idpMetadataMap.size() == 1) {
            return _idpMetadataMap.values().iterator().next();
        }
        return null;
    }

    @Override
    public Collection<SAMLProviderMetadata> getAllIdPMetadata() {
        return _idpMetadataMap.values();
    }

    public Boolean isSAMLPluginEnabled() {
        return SAMLIsPluginEnabled.value();
    }

    @Override
    public String getConfigComponentName() {
        return "SAML2-PLUGIN";
    }

    @Override
    public ConfigKey<?>[] getConfigKeys() {
        return new ConfigKey<?>[] {
                SAMLIsPluginEnabled, SAMLServiceProviderID,
                SAMLServiceProviderContactPersonName, SAMLServiceProviderContactEmail,
                SAMLServiceProviderOrgName, SAMLServiceProviderOrgUrl,
                SAMLServiceProviderSingleSignOnURL, SAMLServiceProviderSingleLogOutURL,
                SAMLCloudStackRedirectionUrl, SAMLUserAttributeName,
                SAMLDefaultDomain,
                SAMLIdentityProviderMetadataURL, SAMLDefaultIdentityProviderId,
                SAMLSignatureAlgorithm, SAMLTimeout};
    }
}
