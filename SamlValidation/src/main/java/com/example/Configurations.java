/**
 * Created by ilian on 2/10/2016.
 */

package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Configurations {

    @Value("${saml-response-file}")
    private String samlResponseFile;

    @Value("${public-certificate-file}")
    private String publicCertificateFile;

    public String getSamlResponseFile() {
        return samlResponseFile;
    }

    public String getPublicCertificateFile() {
        return publicCertificateFile;
    }
}
