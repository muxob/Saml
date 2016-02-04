/**
 * Created by ilian on 2/4/2016.
 */

package com.example;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class SignSamlResponse {

    @Autowired
    private Configurations configurations;

    public Element createSignedSamlResponse() throws SamlException {
        Assertion assertion = createAssertion(configurations.getUserID(), configurations.getBmid());
        Response response = createResponse(assertion);
        Element samlResponse = signTheResponse(response);
        return samlResponse;
    }

    /**
     * Factory for creating SAML objects
     */
    private static XMLObjectBuilderFactory builderFactory;
    private static XMLObjectBuilderFactory getSAMLBuilder() throws SamlException {
        if(builderFactory == null){
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new SamlException(e);
            }
            builderFactory = org.opensaml.Configuration.getBuilderFactory();
        }
        return builderFactory;
    }

    /**
     * Create SMAL assertion
     * @param userID subject
     * @param bmid attribute value
     * @return SMAL assertion
     * @throws SamlException
     */
    private Assertion createAssertion(String userID, String bmid) throws SamlException {
        AssertionBuilder assertionBuilder = (AssertionBuilder) getSAMLBuilder().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(UUID.randomUUID().toString());
        assertion.setIssueInstant(new DateTime(new Date()));

        IssuerBuilder issuerBuilder = (IssuerBuilder) getSAMLBuilder().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(configurations.getIssuer());
        assertion.setIssuer(issuer);

        NameIDBuilder nameidBuilder = (NameIDBuilder) getSAMLBuilder().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameidBuilder.buildObject();
        nameID.setValue(userID);
        //nameID.setFormat(NameIDType.PERSISTENT);

        SubjectBuilder subjectBuilder = (SubjectBuilder) getSAMLBuilder().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameID);
        SubjectConfirmationBuilder scBuilder = (SubjectConfirmationBuilder) getSAMLBuilder().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = scBuilder.buildObject();
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer"); // SubjectConfirmation.METHOD_BEARER
        SubjectConfirmationDataBuilder scDataBuilder = (SubjectConfirmationDataBuilder) getSAMLBuilder().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData scData = scDataBuilder.buildObject();
        scData.setRecipient(configurations.getConsumer());
        Calendar cal = Calendar.getInstance();
        cal.add(12, 30);
        scData.setNotOnOrAfter(new DateTime(cal.getTime().getTime()));
        subjectConfirmation.setSubjectConfirmationData(scData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);

        ConditionsBuilder conditionsBuilder = (ConditionsBuilder) getSAMLBuilder().getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotOnOrAfter(new DateTime(cal.getTime().getTime()));

        AudienceBuilder audienceBuilder = (AudienceBuilder) getSAMLBuilder().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        Audience audience = audienceBuilder.buildObject();
        try {
            URI ex = new URI(configurations.getConsumer());
            audience.setAudienceURI(ex.getScheme() + "://" + ex.getHost());
        } catch (URISyntaxException e) {
            throw new SamlException(e);
        }

        AudienceRestrictionBuilder arBuilder = (AudienceRestrictionBuilder) getSAMLBuilder().getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        AudienceRestriction audienceRestriction = arBuilder.buildObject();
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        assertion.setConditions(conditions);

        AttributeBuilder attributeBuilder = (AttributeBuilder) getSAMLBuilder().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(configurations.getAttributeName());
        attribute.setNameFormat(Attribute.BASIC);
        XSString xsString = new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        xsString.setValue(bmid);
        attribute.getAttributeValues().add(xsString);

        AttributeStatementBuilder atBuilder = (AttributeStatementBuilder) getSAMLBuilder().getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attributeStatement = atBuilder.buildObject();
        attributeStatement.getAttributes().add(attribute);
        //assertion.getAttributeStatements().add(attributeStatement);

        assertion.getStatements().add(attributeStatement);

        return assertion;
    }

    /**
     * Create SAML Response and add the assertion to is
     * @param assertion saml assertion
     * @return SAML Response
     */
    private Response createResponse(Assertion assertion) throws SamlException {
        ResponseBuilder responseBuilder = (ResponseBuilder) getSAMLBuilder().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        response.getAssertions().add(assertion);
        response.setID(assertion.getID());
        response.setIssueInstant(new DateTime(new Date()));
        response.setVersion(SAMLVersion.VERSION_20);

        Issuer issuer = ((IssuerBuilder) getSAMLBuilder().getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue(configurations.getIssuer());
        response.setIssuer(issuer);

        StatusCode statusCode = ((StatusCodeBuilder) getSAMLBuilder().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)).buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);

        Status status = ((StatusBuilder) getSAMLBuilder().getBuilder(Status.DEFAULT_ELEMENT_NAME)).buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        return response;
    }

    /**
     * Sign the SAML response and return as XML element
     * @param response SAML response
     * @return signed XML response
     * @throws SamlException
     */
    private Element signTheResponse(Response response) throws SamlException {
        KeyStore keyStore = getKeyStore();
        Credential credential = getCredential(keyStore);
        Signature signature = createSignature(credential);

        MarshallerFactory fac = Configuration.getMarshallerFactory();
        Marshaller marshaller = fac.getMarshaller(response);
        response.setSignature(signature);

        Element responseElement;
        try {
            responseElement = marshaller.marshall(response);
            Signer.signObject(signature);
        } catch (MarshallingException e) {
            throw new SamlException(e);
        } catch (SignatureException e) {
            throw new SamlException(e);
        }

        return responseElement;
    }

    /**
     * Extract keystore
     * @return keystore
     * @throws SamlException
     */
    private KeyStore getKeyStore() throws SamlException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(configurations.getCertificateType());
        } catch (KeyStoreException e) {
            throw new SamlException(e);
        }

        File file = new File(configurations.getCertificateFile());
        try {
            InputStream in = new FileInputStream(file);
            //InputStream in = SignSamlResponse.class.getClassLoader().getResourceAsStream(configurations.getCertificateFile());
            try {
                keyStore.load(in, configurations.getCertificatePassword().toCharArray());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } finally {
                in.close();
            }
        } catch (IOException e) {
            throw new SamlException(e);
        }

        return keyStore;
    }

    /**
     * Generate signed credential from keystore
     * @param keyStore the keyStore
     * @return signed credential
     * @throws SamlException
     */
    private Credential getCredential(KeyStore keyStore) throws SamlException {
        PrivateKey prikey = null;
        PublicKey pubkey = null;
        Collection<X509Certificate> certChain = null;

        try {
            Enumeration<String> keys = keyStore.aliases();
            while (keys.hasMoreElements()) {
                String aliase = keys.nextElement();
                Key key = keyStore.getKey(aliase, configurations.getCertificatePassword().toCharArray());
                if (key != null && key instanceof PrivateKey) {
                    prikey = (PrivateKey) key;
                    pubkey = keyStore.getCertificate(aliase).getPublicKey();
                    java.security.cert.Certificate[] certs = keyStore.getCertificateChain(aliase);
                    certChain = new ArrayList<X509Certificate>();
                    for (java.security.cert.Certificate tempCert : certs) {
                        certChain.add((X509Certificate) tempCert);
                    }
                }
            }
        } catch (Exception e) {
            throw new SamlException(e);
        }

        BasicX509Credential signingCredential = new BasicX509Credential();
        signingCredential.setEntityCertificateChain(certChain);
        signingCredential.setPrivateKey(prikey);
        signingCredential.setPublicKey(pubkey);

        return signingCredential;
    }

    /**
     * Generate Signature from given credential
     * @param credential signed credential
     * @return SAML signature
     * @throws SamlException
     */
    private Signature createSignature(Credential credential) throws SamlException {
        SignatureBuilder signatureBuilder = (SignatureBuilder) getSAMLBuilder().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }
}
