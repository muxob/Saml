/**
 * Created by ilian on 2/4/2016.
 */

package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Configurations {

    @Value("${certificate-file}")
    private String certificateFile;

    @Value("${certificate-password}")
    private String certificatePassword;

    @Value("${certificate-type}")
    private String certificateType;

    @Value("${issuer}")
    private String issuer;

    @Value("${consumer}")
    private String consumer;

    @Value("${attribute-name}")
    private String attributeName;

    @Value("${s4-user-id}")
    private String userID;

    @Value("${s4-org-private-id}")
    private String bmid;

    public String getCertificateFile() {
        return certificateFile;
    }

    public String getCertificatePassword() {
        return certificatePassword;
    }

    public String getCertificateType() {
        return certificateType;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getConsumer() {
        return consumer;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public String getUserID() {
        return userID;
    }

    public String getBmid() {
        return bmid;
    }
}
