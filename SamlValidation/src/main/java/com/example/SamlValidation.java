/**
 * Created by ilian on 2/10/2016.
 */

package com.example;

import org.apache.commons.ssl.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class SamlValidation {

    @Autowired
    private Configurations configurations;

    public void validate() throws SamlException {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new SamlException(e);
        }

        Document samlDocument = loadSamlDocumant();
        //System.out.println(XMLHelper.nodeToString(samlDocument));
        BasicX509Credential credential = getCredential();
        Response response = getValidResponse(samlDocument, credential);
        Assertion theAssertion = response.getAssertions().get(0);
        String userID = getValidUserID(theAssertion, credential);
        if (userID == null) {
            throw new SamlException("No valid user id");
        }
        System.out.println("UserID: " + userID);
        Map<String, String> attributes = getAttributesFromAssertions(response.getAssertions());
        System.out.println("BMID: " + attributes.get("BMID"));
    }

    private Document loadSamlDocumant() throws SamlException {
        try {
            String encodedSaml = new String(Files.readAllBytes(Paths.get(configurations.getSamlResponseFile())));
            String urlDecoded = URLDecoder.decode(encodedSaml, "UTF-8");
            String xmlSource = new String(Base64.decodeBase64(urlDecoded.getBytes()));

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new InputSource(new StringReader(xmlSource)));
        } catch (Exception e) {
            throw new SamlException(e);
        }
    }

    private Response getValidResponse(Document samlDocument, BasicX509Credential credential) throws SamlException {
        Element responseElement = samlDocument.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(responseElement);
        Response response;
        try {
            response = (Response) unmarshaller.unmarshall(responseElement);
        } catch (UnmarshallingException e) {
            throw new SamlException(e);
        }

        if(!response.isSigned()) {
            throw new SamlException("Response is not signed.");
        }

        Signature signature = response.getSignature();
        SAMLSignatureProfileValidator signProfValidator = new SAMLSignatureProfileValidator();
        try {
            signProfValidator.validate(signature);
        } catch (ValidationException e) {
            throw new SamlException(e);
        }

        SignatureValidator sigValidator = new SignatureValidator(credential);
        try {
            sigValidator.validate(signature);
        } catch (ValidationException e) {
            throw new SamlException(e);
        }

        return  response;
    }

    private KeyStore getKeyStore() throws SamlException {
        KeyStore keyStore;
        File file = new File(configurations.getPublicCertificateFile());

        try {
            InputStream in = new FileInputStream(file);

            try {
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(null, null);
                keyStore.setCertificateEntry(configurations.getCertificateType(), certificate);
            } catch (Exception e) {
                throw new SamlException(e);
            } finally {
                in.close();
            }
        } catch (IOException e) {
            throw new SamlException(e);
        }

        return keyStore;
    }

    private BasicX509Credential getCredential() throws SamlException {
        BasicX509Credential cred = null;
        KeyStore keyStore = getKeyStore();

        try {
            Enumeration aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                if(cert != null) {
                    cred = new BasicX509Credential();
                    cred.setEntityCertificate(cert);
                    cred.setPublicKey(cert.getPublicKey());
                }
            }
        } catch (KeyStoreException e) {
            throw new SamlException(e);
        }

        if (cred == null) {
            throw new SamlException("No certificate in the keystore");
        }
        return cred;
    }

    private String getValidUserID(Assertion assertion, BasicX509Credential credential) throws SamlException {
        if (isValidCondition(assertion)) {
            Subject subject = assertion.getSubject();
            if (subject != null) {
                if (isValidSubject(subject)) {
                    if (subject.getNameID() != null) {
                        return subject.getNameID().getValue();
                    }

                    // this hasn't been tested
                    if (subject.getEncryptedID() != null) {
                        StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
                        Decrypter decrypter = new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
                        SAMLObject object;
                        try {
                            object = decrypter.decrypt(subject.getEncryptedID());
                        } catch (DecryptionException e) {
                            throw new SamlException(e);
                        }
                        if (object instanceof NameID) {
                            NameID nameObj = (NameID) object;
                            return nameObj.getValue();
                        }
                        throw new SamlException("Only NameID supported for encryption in Assertion");
                    }
                }
            }
        }

        return null;
    }

    private boolean isValidCondition(Assertion assertion) {
        Date now = new Date();
        Conditions conditions = assertion.getConditions();
        if(conditions != null) {
            DateTime notOnOrAfter;
            long time;
            long currentTime;
            if(conditions.getNotBefore() != null) {
                notOnOrAfter = conditions.getNotBefore();
                time = notOnOrAfter.getMillis();
                currentTime = now.getTime();
                if(time >= currentTime) {
                    return false;
                }
            }

            if(conditions.getNotOnOrAfter() != null) {
                notOnOrAfter = conditions.getNotOnOrAfter();
                time = notOnOrAfter.getMillis();
                currentTime = now.getTime();
                if(currentTime >= time) {
                    return false;
                }
            }
        }

        return true;
    }

    private boolean isValidSubject(Subject subject) {
        List confirmations = subject.getSubjectConfirmations();
        Date now = new Date();
        boolean ret = true;
        if(confirmations == null) {
            return true;
        } else {
            Iterator i$ = confirmations.iterator();

            while(true) {
                while(true) {
                    SubjectConfirmationData data;
                    do {
                        if(!i$.hasNext()) {
                            return ret;
                        }

                        SubjectConfirmation confirmation = (SubjectConfirmation)i$.next();
                        data = confirmation.getSubjectConfirmationData();
                    } while(data == null);

                    DateTime notOnOrAfter;
                    long time;
                    long currentTime;
                    if(data.getNotBefore() != null) {
                        notOnOrAfter = data.getNotBefore();
                        time = notOnOrAfter.getMillis();
                        currentTime = now.getTime();
                        if(time >= currentTime) {
                            ret = false;
                            continue;
                        }
                    }

                    if(data.getNotOnOrAfter() != null) {
                        notOnOrAfter = data.getNotOnOrAfter();
                        time = notOnOrAfter.getMillis();
                        currentTime = now.getTime();
                        if(currentTime >= time) {
                            ret = false;
                        }
                    }
                }
            }
        }
    }

    private Map<String, String> getAttributesFromAssertions(List<Assertion> assertions) {
        Map<String, String> attributesMap = new HashMap<>();
        for (Assertion assertion : assertions) {
            for (Statement statement : assertion.getStatements()) {
                if (statement instanceof AttributeStatement) {
                    for (Attribute attribute : ((AttributeStatement) statement).getAttributes()) {
                        if (attribute != null && attribute.getAttributeValues() != null && !attribute.getAttributeValues().isEmpty()) {
                            XSString attribValue = (XSString) attribute.getAttributeValues().get(0);
                            if (attribValue != null && attribValue.getValue() != null && !attribValue.getValue().isEmpty()) {
                                attributesMap.put(attribute.getName(), attribValue.getValue());
                            }
                        }
                    }
                }
            }
        }
        return attributesMap;
    }
}
