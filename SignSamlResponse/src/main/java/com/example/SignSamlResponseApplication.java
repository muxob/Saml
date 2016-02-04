package com.example;


import org.apache.commons.ssl.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.w3c.dom.Element;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@SpringBootApplication
public class SignSamlResponseApplication implements CommandLineRunner {

	@Autowired
	private SignSamlResponse signSamlResponse;

	@Override
	public void run(String... args) {
		Element samlResponse;
		try {
			samlResponse = signSamlResponse.createSignedSamlResponse();
		} catch (SamlException e) {
			throw new RuntimeException(e);
		}
		String originalAssertionString = XMLHelper.nodeToString(samlResponse);
		System.out.println("Response String:\r\n" + originalAssertionString);

		try {
			System.out.println();
			byte[] base64encoded = Base64.encodeBase64(originalAssertionString.getBytes());
			System.out.println("http://sofn60270530a:1983/scripts/WebObjects.dll/Supplier.woa/ad/bpMigration?SendUpdateToBP=false&SAMLResponse=" + URLEncoder.encode(new String(base64encoded), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SignSamlResponseApplication.class, args);
		if (args.length < 2) {
			System.out.println("\r\nusage:\r\njava -jar " + SignSamlResponse.class.getSimpleName() + ".jar --s4-user-id=<s4-user-id> --s4-org-private-id=<s4_org_private_id>");
			System.out.println("java -jar " + SignSamlResponse.class.getSimpleName() + ".jar --s4-user-id=<s4-user-id> --s4-org-private-id=<s4_org_private_id> --certificate-file=../cert/bp-test.p12 --certificate-password=<password> --certificate-type=pkcs12");
			System.out.println("other parameters: --issuer; --consumer; --attribute-name");
		}
	}
}
