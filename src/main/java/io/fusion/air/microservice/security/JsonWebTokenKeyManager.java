/**
 * (C) Copyright 2021 Araf Karsh Hamid
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.fusion.air.microservice.security;

// Spring
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
// Java
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
// Logger
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;
import static java.lang.invoke.MethodHandles.lookup;

/**
 * JsonWebToken Key Manager
 * Loads Secret Key, Public Keys depends upon the configuration.
 *
 * @author arafkarsh
 *
 */
@Service
public final class JsonWebTokenKeyManager {

	// Set Logger -> Lookup will automatically determine the class name.
	private static final Logger log = getLogger(lookup().lookupClass());

	@Autowired
	private JsonWebTokenConfig jwtConfig;

	@Autowired
	private KeyCloakConfig keycloakConfig;

	@Autowired
	private CryptoKeyGenerator cryptoKeys;

	private int tokenType;

	private Key signingKey;
	private Key validatorKey;
	private Key validatorLocalKey;

	// private SignatureAlgorithm algorithm;
	// public final static SignatureAlgorithm defaultAlgo = SignatureAlgorithm.HS512;

	private String issuer;

	/**
	 * Initialize the JWT with the Signature Algorithm based on Secret Key or Public / Private Key
	 */
	public JsonWebTokenKeyManager() {
	}

	/**
	 * Initialize the JsonWebToken with Token Type Secret Keys and other default claims
	 * settings.
	 * @return
	 */
	public JsonWebTokenKeyManager init() {
		return init(JsonWebTokenConstants.SECRET_KEY);
	}

	/**
	 * Initialize the JsonWebToken with Token Type (Secret or Public/Private Keys) and other default claims
	 * settings.
	 * @return
	 */
	public JsonWebTokenKeyManager init(int _tokenType) {
		tokenType 			= _tokenType;
		log.debug("JWT-KeyManager: JSON Web Token Type = "+tokenType);
		// Create the Key based on Secret Key or Private Key
		createSigningKey();
		issuer				= (jwtConfig != null) ? jwtConfig.getServiceOrg() : "fusion-air";
		return this;
	}

	/**
	 * Create the Key based on  Secret Key or Public / Private Key
	 *
	 * @return
	 */
	private void createSigningKey() {
		switch(tokenType) {
			case JsonWebTokenConstants.SECRET_KEY:
				log.info("JWT-KeyManager: JSON Web Token based on SECRET KEY....");
				signingKey = new SecretKeySpec(getTokenKeyBytes(), "HmacSHA512");
				validatorKey = signingKey;
				validatorLocalKey = signingKey;
				break;
			case JsonWebTokenConstants.PUBLIC_KEY:
				log.info("JWT-KeyManager: JSON Web Token based on PUBLIC KEY....");
				getCryptoKeyGenerator()
				.setKeyFiles(getCryptoPublicKeyFile(), getCryptoPrivateKeyFile())
				.iFPublicPrivateKeyFileNotFound().THEN()
					.createRSAKeyFiles()
				.ELSE()
					.readRSAKeyFiles()
				.build();
				signingKey = getCryptoKeyGenerator().getPrivateKey();
				validatorKey = getCryptoKeyGenerator().getPublicKey();
				validatorLocalKey = validatorKey;
				System.out.println("Public key format: " + getCryptoKeyGenerator().getPublicKey().getFormat());
				System.out.println(getCryptoKeyGenerator().getPublicKeyPEMFormat());
				break;
		}
	}

	/**
	 * This is set when the Applications Boots Up from the Servlet Event Listener
	 * Servlet Event Listener ensures that the public key is downloaded from the KeyCloak Server
	 * Set the Validator Key as KeyCloak Public Key if the Public Key downloaded from KeyCloak.
	 */
	public void setKeyCloakPublicKey() {
		if(keycloakConfig.isKeyCloakEnabled()) {
			log.info("JWT-KeyManager: KeyCloak Server Access Enabled.... ");
			Path filePath = Paths.get(keycloakConfig.getKeyCloakPublicKey());
			RSAPublicKey key = null;
			String keyName = "RSA PUBLIC KEY";
			if (Files.exists(filePath)) {
				try {
					getCryptoKeyGenerator()
						.setPublicKeyFromKeyCloak(
							getCryptoKeyGenerator()
							.readPublicKey(new File(keycloakConfig.getKeyCloakPublicKey()))
						);
					issuer = keycloakConfig.getTokenIssuer();
					validatorKey = getCryptoKeyGenerator().getPublicKey();
					String pem = getCryptoKeyGenerator().convertKeyToText(getValidatorKey(), keyName);
					log.info("KeyCloak Public Key Set. Issuer = "+issuer);
					// System.out.println("KeyCloak Public Key Set. Issuer = "+issuer);
					System.out.println(pem);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	/**
	 * Returns Crypto Public Key File
	 * @return
	 */
	private String getCryptoPublicKeyFile() {
		return (jwtConfig != null) ? jwtConfig.getCryptoPublicKeyFile() : "publicKey.pem";
	}

	/**
	 * Returns Crypto Private Key File
	 * @return
	 */
	private String getCryptoPrivateKeyFile() {
		return (jwtConfig != null) ? jwtConfig.getCryptoPrivateKeyFile() : "privateKey.pem";
	}

	/**
	 * Returns Token Key -
	 * In SpringBooT Context from ServiceConfiguration
	 * Else from Static TOKEN Key
	 * @return
	 */
	private String getTokenKey() {
		return (jwtConfig != null) ? jwtConfig.getTokenKey() : JsonWebTokenConstants.TOKEN;
	}

	/**
	 * Returns the Token Key in Bytes
	 * @return
	 */
	private byte[] getTokenKeyBytes() {
		return HashData.base64Encoder(getTokenKey()).getBytes();
	}

	/**
	 * Returns CryptoKeyGenerator
	 * @return
	 */
	private CryptoKeyGenerator getCryptoKeyGenerator() {
		if(cryptoKeys == null) {
			cryptoKeys = new CryptoKeyGenerator();
		}
		return cryptoKeys;
	}

	/**
	 * Set the Issuer
	 * @param _issuer
	 * @return
	 */
	public JsonWebTokenKeyManager setIssuer(String _issuer) {
		issuer = _issuer;
		return this;
	}

	/**
	 * Returns the Issuer
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * Returns the Signing Key
	 * @return
	 */
	public Key getKey() {
		return signingKey;
	}

	/**
	 * Returns KeyCloak Validator (Public) Key
	 * @return
	 */
	public Key getValidatorKey() {
		return validatorKey;
	}

	/**
	 * Returns Validator Local Key
	 * @return
	 */
	public Key getValidatorLocalKey() {
		return validatorLocalKey;
	}
}
