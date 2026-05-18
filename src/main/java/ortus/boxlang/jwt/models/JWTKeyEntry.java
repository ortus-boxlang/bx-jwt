/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Holds a parsed named key entry from the module settings. Stores the
 * algorithm, and up to three key representations: private, public, and
 * secret (HMAC). Null fields indicate that side is not configured.
 */
package ortus.boxlang.jwt.models;

import java.security.Key;

public class JWTKeyEntry {

	String	name;
	String	algorithm;
	Key		privateKey;
	Key		publicKey;
	Key		secretKey;

	public JWTKeyEntry( String name, String algorithm ) {
		this.name		= name;
		this.algorithm	= algorithm;
	}

	/**
	 * Constructs a JWTKeyEntry with a name and algorithm.
	 *
	 * @param name      The name of the key entry.
	 * @param algorithm The algorithm for the key entry.
	 */

	public JWTKeyEntry( String name, String algorithm, Key privateKey, Key publicKey, Key secretKey ) {
		this.name		= name;
		this.algorithm	= algorithm;
		this.privateKey	= privateKey;
		this.publicKey	= publicKey;
		this.secretKey	= secretKey;
	}

	/**
	 * Constructs a JWTKeyEntry with all key types.
	 *
	 * @param name       The name of the key entry.
	 * @param algorithm  The algorithm for the key entry.
	 * @param privateKey The private key, or null if not configured.
	 * @param publicKey  The public key, or null if not configured.
	 * @param secretKey  The secret (HMAC) key, or null if not configured.
	 */

	public String getName() {
		return name;
	}

	/**
	 * Gets the name of the key entry.
	 *
	 * @return The name of the key entry.
	 */

	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * Gets the algorithm of the key entry.
	 *
	 * @return The algorithm.
	 */

	public Key getPrivateKey() {
		return privateKey;
	}

	/**
	 * Gets the private key.
	 *
	 * @return The private key, or null if not configured.
	 */

	public void setPrivateKey( Key privateKey ) {
		this.privateKey = privateKey;
	}

	/**
	 * Sets the private key.
	 *
	 * @param privateKey The private key to set.
	 */

	public Key getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the public key.
	 *
	 * @return The public key, or null if not configured.
	 */

	public void setPublicKey( Key publicKey ) {
		this.publicKey = publicKey;
	}

	/**
	 * Sets the public key.
	 *
	 * @param publicKey The public key to set.
	 */

	public Key getSecretKey() {
		return secretKey;
	}

	/**
	 * Gets the secret (HMAC) key.
	 *
	 * @return The secret key, or null if not configured.
	 */

	public void setSecretKey( Key secretKey ) {
		this.secretKey = secretKey;
	}

	/**
	 * Sets the secret (HMAC) key.
	 *
	 * @param secretKey The secret key to set.
	 */

	public boolean hasPrivateKey() {
		return privateKey != null;
	}

	/**
	 * Checks if a private key is configured.
	 *
	 * @return True if a private key is present, false otherwise.
	 */

	public boolean hasPublicKey() {
		return publicKey != null;
	}

	/**
	 * Checks if a public key is configured.
	 *
	 * @return True if a public key is present, false otherwise.
	 */

	public boolean hasSecretKey() {
		return secretKey != null;
	}
	/**
	 * Checks if a secret (HMAC) key is configured.
	 *
	 * @return True if a secret key is present, false otherwise.
	 */

}
