/**
 * Created by ilian on 2/10/2016.
 */

package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SamlValidationApplication implements CommandLineRunner {

    @Autowired
    private SamlValidation samlValidation;

    @Override
    public void run(String... args) {
        try {
            samlValidation.validate();
        } catch (SamlException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("\r\nusage:\r\njava -jar " + SamlValidation.class.getSimpleName() + ".jar --saml-response-file=<path_to_base64_url_encripted_saml_response>");
            System.out.println("java -jar " + SamlValidation.class.getSimpleName() + ".jar --saml-response-file=../ioFiles/exampleSamlResponse.base64 --public-certificate-file=../cert/bp-test.crt");
            System.out.println("other parameters: --certificate-type=cert");
            return;
        }
        SpringApplication.run(SamlValidationApplication.class, args);
    }
}
