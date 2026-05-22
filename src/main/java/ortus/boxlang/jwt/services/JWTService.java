/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Backbone service for the bx-jwt module. Manages the named key registry,
 * key parsing (PEM, JWK, raw secrets), and delegates JWS creation/verification
 * and JWE encryption/decryption to Nimbus JOSE+JWT.
 * <p>
 * Auto-registered via ServiceLoader as an {@code IService}.
 */
package ortus.boxlang.jwt.services;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ortus.boxlang.jwt.exceptions.JWTEncryptionException;
import ortus.boxlang.jwt.exceptions.JWTExpiredException;
import ortus.boxlang.jwt.exceptions.JWTKeyException;
import ortus.boxlang.jwt.exceptions.JWTNotYetValidException;
import ortus.boxlang.jwt.exceptions.JWTParseException;
import ortus.boxlang.jwt.exceptions.JWTVerificationException;
import ortus.boxlang.jwt.models.JWTKeyEntry;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.config.util.PlaceholderHelper;
import ortus.boxlang.runtime.dynamic.casters.BooleanCaster;
import ortus.boxlang.runtime.dynamic.casters.LongCaster;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.logging.BoxLangLogger;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.services.BaseService;
import ortus.boxlang.runtime.types.Array;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

public class JWTService extends BaseService {

	/**
	 * --------------------------------------------------------------------------
	 * Private Properties
	 * --------------------------------------------------------------------------
	 */

	private ConcurrentHashMap<String, JWTKeyEntry>	keyRegistry			= new ConcurrentHashMap<>();

	/**
	 * Module settings are accessed frequently for defaults, so we cache them in a static struct for quick access.
	 */
	private static final IStruct					MODULE_SETTINGS		= BoxRuntime.getInstance()
	    .getModuleService()
	    .getModuleSettings( KeyDictionary.moduleName );

	/**
	 * Logger instance for the JWTService class. Used for logging key registration, JWT operations, and error conditions.
	 */
	private static final BoxLangLogger				logger				= BoxRuntime.getInstance().getLoggingService().APPLICATION_LOGGER;

	/**
	 * Default clock skew in seconds for validating time-based claims (exp, nbf) when no specific skew is provided in options or module settings.
	 */
	private static final long						DEFAULT_CLOCK_SKEW	= 60L;

	/**
	 * --------------------------------------------------------------------------
	 * Constructor(s)
	 * --------------------------------------------------------------------------
	 */

	/**
	 * Constructs a JWTService using the default BoxRuntime instance.
	 */
	public JWTService() {
		this( BoxRuntime.getInstance() );
	}

	/**
	 * Constructs a JWTService with a specific BoxRuntime instance.
	 *
	 * @param runtime The BoxRuntime instance to use.
	 */
	public JWTService( BoxRuntime runtime ) {
		super( runtime, KeyDictionary.JWTService );
	}

	/**
	 * --------------------------------------------------------------------------
	 * Runtime Service Event Methods
	 * --------------------------------------------------------------------------
	 */

	/**
	 * Called when the service configuration is loaded.
	 * (No-op for JWTService.)
	 */
	@Override
	public void onConfigurationLoad() {
	}

	/**
	 * Called when the service is started up. Parses configured keys.
	 */
	@Override
	public void onStartup() {
		parseConfiguredKeys();
		logger.trace( "JWTService startup complete. Registered keys: {}", keyRegistry.keySet() );
	}

	/**
	 * Called when the service is shut down. Clears the key registry.
	 *
	 * @param force Whether the shutdown is forced.
	 */
	@Override
	public void onShutdown( Boolean force ) {
		this.keyRegistry.clear();
		logger.trace( "JWTService shutdown complete. Key registry cleared." );
	}

	/**
	 * --------------------------------------------------------------------------
	 * Key Management Operations
	 * --------------------------------------------------------------------------
	 */

	/**
	 * Registers a key in the service's key registry with the given name and configuration.
	 *
	 * @param name      The name of the key to register.
	 * @param keyConfig The configuration for the key.
	 *
	 * @return
	 */
	public JWTKeyEntry registerKey( String name, IStruct keyConfig ) {
		String algorithm = StringCaster.cast( keyConfig.getOrDefault( KeyDictionary.algorithm, "" ) );
		if ( algorithm.isEmpty() ) {
			throw new JWTKeyException( "Key \"" + name + "\" is missing required field: algorithm" );
		}

		JWTKeyEntry	entry		= new JWTKeyEntry( name, algorithm );
		Object		secretVal	= keyConfig.get( KeyDictionary.secret );
		if ( secretVal != null ) {
			String secret = PlaceholderHelper.resolve( StringCaster.cast( secretVal ) );
			entry.setSecretKey( parseHmacSecret( secret, algorithm ) );
		}

		Object privKeyVal = keyConfig.get( KeyDictionary.privateKey );
		if ( privKeyVal != null ) {
			entry.setPrivateKey( parsePemKey( StringCaster.cast( privKeyVal ), true ) );
		}

		Object pubKeyVal = keyConfig.get( KeyDictionary.publicKey );
		if ( pubKeyVal != null ) {
			entry.setPublicKey( parsePemKey( StringCaster.cast( pubKeyVal ), false ) );
		}

		Object jwkVal = keyConfig.get( KeyDictionary.jwk );
		if ( jwkVal != null ) {
			IStruct				jwkStruct	= StructCaster.cast( jwkVal );
			java.security.Key	jwkKey		= parseJwkStruct( jwkStruct );
			if ( jwkKey instanceof PrivateKey ) {
				entry.setPrivateKey( ( PrivateKey ) jwkKey );
			} else if ( jwkKey instanceof PublicKey ) {
				entry.setPublicKey( ( PublicKey ) jwkKey );
			} else if ( jwkKey instanceof SecretKey ) {
				entry.setSecretKey( ( SecretKey ) jwkKey );
			}
		}

		this.keyRegistry.put( name, entry );
		return entry;
	}

	/**
	 * Get a registered key entry by name.
	 *
	 * @param name The name of the key to retrieve.
	 *
	 * @throws JWTKeyException if the key is not found in the registry.
	 *
	 * @return The JWTKeyEntry associated with the given name.
	 */
	public JWTKeyEntry getKey( String name ) {
		JWTKeyEntry entry = this.keyRegistry.get( name );
		if ( entry == null ) {
			throw new JWTKeyException( "Key \"" + name + "\" is not registered" );
		}
		return entry;
	}

	/**
	 * Removes a registered key entry by name.
	 *
	 * @param name The name of the key to remove.
	 */
	public void removeKey( String name ) {
		this.keyRegistry.remove( name );
	}

	/**
	 * Clears all registered key entries.
	 */
	public void clearKeys() {
		this.keyRegistry.clear();
	}

	/**
	 * Returns an array of all registered key names.
	 *
	 * @return An Array containing the names of all registered keys.
	 */
	public Array getKeyNames() {
		return Array.fromSet( this.keyRegistry.keySet() );
	}

	/**
	 * Checks if a key with the given name is registered.
	 *
	 * @param name The name of the key to check.
	 *
	 * @return true if the key is registered, false otherwise.
	 */
	public boolean hasKey( String name ) {
		return keyRegistry.containsKey( name );
	}

	/**
	 * --------------------------------------------------------------------------
	 * JWT REsolutions + Parsing
	 * --------------------------------------------------------------------------
	 */

	/**
	 * Resolve the signing key from the registered keys based on the provided key name or defaults.
	 *
	 * @param name The name of the key to resolve for signing.
	 *
	 * @return The resolved signing key.
	 */
	public java.security.Key resolveSigningKey( String name ) {
		JWTKeyEntry entry = getKey( name );
		if ( entry.hasPrivateKey() ) {
			return entry.getPrivateKey();
		}
		if ( entry.hasSecretKey() ) {
			return entry.getSecretKey();
		}
		throw new JWTKeyException( "Key \"" + name + "\" has no private key or secret key for signing" );
	}

	/**
	 * Resolve the verification key from the registered keys based on the provided key name or defaults.
	 *
	 * @param name The name of the key to resolve for verification.
	 *
	 * @return The resolved verification key.
	 */
	public java.security.Key resolveVerificationKey( String name ) {
		JWTKeyEntry entry = getKey( name );
		if ( entry.hasPublicKey() ) {
			return entry.getPublicKey();
		}
		if ( entry.hasSecretKey() ) {
			return entry.getSecretKey();
		}
		throw new JWTKeyException( "Key \"" + name + "\" has no public key or secret key for verification" );
	}

	/**
	 * Resolve the encryption key from the registered keys based on the provided key name or defaults.
	 *
	 * @param name The name of the key to resolve for encryption.
	 *
	 * @return The resolved encryption key.
	 */
	public java.security.Key resolveEncryptionKey( String name ) {
		JWTKeyEntry entry = getKey( name );
		if ( entry.hasPublicKey() ) {
			return entry.getPublicKey();
		}
		if ( entry.hasSecretKey() ) {
			return entry.getSecretKey();
		}
		throw new JWTKeyException( "Key \"" + name + "\" has no public key or secret key for encryption" );
	}

	/**
	 * Resolve the decryption key from the registered keys based on the provided key name or defaults.
	 *
	 * @param name The name of the key to resolve for decryption.
	 *
	 * @return The resolved decryption key.
	 */
	public java.security.Key resolveDecryptionKey( String name ) {
		JWTKeyEntry entry = getKey( name );
		if ( entry.hasPrivateKey() ) {
			return entry.getPrivateKey();
		}
		if ( entry.hasSecretKey() ) {
			return entry.getSecretKey();
		}
		throw new JWTKeyException( "Key \"" + name + "\" has no private key or secret key for decryption" );
	}

	/**
	 * Parses a key from various formats such as named keys, PEM strings, JWK structs, or raw secrets.
	 * If it's already a java.security.Key instance, it is returned directly.
	 *
	 * @param keyArg    The key argument to parse.
	 * @param algorithm The algorithm to use for parsing the key.
	 *
	 * @throws JWTKeyException if the key cannot be parsed or is invalid for the specified algorithm.
	 *
	 * @return The parsed key.
	 */
	public java.security.Key parseKey( Object keyArg, String algorithm ) {
		if ( keyArg == null ) {
			throw new JWTKeyException( "Key argument is null. Provide a named key, PEM string, JWK struct, or raw secret." );
		}
		if ( keyArg instanceof java.security.Key jKey ) {
			return jKey;
		}

		String keyStr = StringCaster.cast( keyArg );

		// If the string looks like a PEM-encoded key, attempt to parse it as PEM. This covers both private and public keys.
		if ( keyStr.contains( "-----BEGIN" ) ) {
			boolean isPrivate = keyStr.contains( "PRIVATE" );
			return parsePemString( keyStr.strip(), isPrivate );
		}
		// If the string looks like a JSON object, attempt to parse it as a JWK. This covers both symmetric and asymmetric keys.
		if ( isHmacAlgorithm( algorithm ) ) {
			return parseHmacSecret( keyStr, algorithm );
		}
		// Non-HMAC algorithm with a plain string key — treat as an HMAC secret anyway since
		// parseHmacSecret never throws. The Nimbus signer/verifier will reject the key type
		// mismatch with a clear JOSEException if the algorithm is truly asymmetric.
		return parseHmacSecret( keyStr, "HS256" );
	}

	/**
	 * --------------------------------------------------------------------------
	 * JWT Creation + Encryption + Verification + Decryption
	 * --------------------------------------------------------------------------
	 */

	/**
	 * BIF implementation for JWT encryption. Accepts a payload, encryption key material, and options to produce a JWE string.
	 *
	 * @param payload   The claims payload to encrypt, which can be a struct or any value that can be stringified.
	 * @param key       The encryption key material, which can be a named key, PEM/JWK string, or raw secret. Optional if defaultEncryptionKey is
	 *                  configured.
	 * @param algorithm The encryption algorithm to use (e.g., "RSA-OAEP-256", "A256GCM"). Optional if resolved from key metadata or defaults.
	 * @param options   Additional encryption options such as custom JOSE headers, keyAlgorithm, and encAlgorithm.
	 *
	 * @return A compact serialized JWE string containing the encrypted payload.
	 */
	public String create( IStruct payload, java.security.Key key, String algorithm, IStruct options ) {
		try {
			// Parse the algorithm accordingly and create the signer.
			JWSAlgorithm			alg				= JWSAlgorithm.parse( algorithm );
			JWSSigner				signer			= createSigner( key, alg );
			// Build the appropriate claims requested in the payload, and apply any custom headers from options.
			// The service method handles the actual signing and serialization of the JWT.
			JWTClaimsSet.Builder	claimsBuilder	= buildClaims( payload, options );
			// Build the header now for the JWT
			JWSHeader.Builder		headerBuilder	= new JWSHeader.Builder( alg );
			// Apply any custom headers from options to the header builder. This allows users to include additional JOSE headers as needed.
			applyHeaders( headerBuilder, options );
			SignedJWT signedJWT = new SignedJWT( headerBuilder.build(), claimsBuilder.build() );
			signedJWT.sign( signer );
			return signedJWT.serialize();
		} catch ( JOSEException e ) {
			throw new JWTVerificationException( "Failed to sign JWT: " + e.getMessage(), e );
		} catch ( Exception e ) {
			throw new JWTParseException( "Failed to create JWT: " + e.getMessage(), e );
		}
	}

	/**
	 * BIF implementation for JWT verification. Accepts a JWT token, verification key material, algorithm, and options to validate the token and return
	 * the claims.
	 *
	 * @param token     The JWT token to verify.
	 * @param key       The verification key material, which can be a named key, PEM/JWK string, or raw secret. Optional if defaultVerificationKey is
	 *                  configured.
	 * @param algorithm The verification algorithm to use (e.g., "RS256", "HS256"). Optional if resolved from key metadata or defaults.
	 * @param options   Additional verification options such as custom JOSE headers, leeway, and claim checks.
	 *
	 * @throws JWTVerificationException if the token fails signature verification or claim validation.
	 * @throws JWTExpiredException      if the token is expired based on the "exp" claim and current time.
	 * @throws JWTNotYetValidException  if the token is not yet valid based on the "nbf" claim and current time.
	 * @throws JWTParseException        if the token cannot be parsed as a valid JWT structure.
	 *
	 * @return The claims contained in the verified JWT.
	 */
	public IStruct verify( String token, java.security.Key key, String algorithm, IStruct options ) {
		try {
			// Algorithm resolution is handled in the resolveAlgorithm method, which considers the explicit argument, key metadata, and defaults.
			JWSAlgorithm	alg			= JWSAlgorithm.parse( algorithm );
			// Create the appropriate JWSVerifier based on the key type and algorithm. This supports RSA, EC, and HMAC keys.
			SignedJWT		signedJWT	= SignedJWT.parse( token );
			// Verify the signature and validate the claims. If verification fails, a JWTVerificationException is thrown.
			// If the token is expired or not yet valid, specific exceptions are thrown.
			JWSVerifier		verifier	= createVerifier( key, alg );
			// Nimbus's verify method returns a boolean, so we check the result and throw an exception if verification fails. This allows us to provide a
			// consistent exception type for signature verification failures.
			if ( !signedJWT.verify( verifier ) ) {
				throw new JWTVerificationException( "JWT signature verification failed" );
			}

			// If we get here the signature is valid, so we proceed to validate the claims based on the provided options.
			// This includes checks for expiration, not-before, issuer, audience, and any custom claim validations specified in the options.
			// If claim validation fails, a JWTVerificationException is thrown with details about the failure.
			JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
			validateClaims( claimsSet, options );
			// Type them to a BoxLang Struct
			return claimsToStruct( claimsSet );
		} catch ( JWTVerificationException e ) {
			throw e;
		} catch ( JWTExpiredException e ) {
			throw e;
		} catch ( JWTNotYetValidException e ) {
			throw e;
		} catch ( JOSEException e ) {
			throw new JWTVerificationException( "Failed to verify JWT: " + e.getMessage(), e );
		} catch ( Exception e ) {
			throw new JWTParseException( "Failed to parse JWT: " + e.getMessage(), e );
		}
	}

	/**
	 * BIF implementation for JWT decryption. Accepts a JWE token, decryption key material, and options to return the decrypted payload.
	 * For structured payloads, this returns a claims struct. For nested JWT scenarios, the returned struct includes
	 * the nested payload string for follow-up verification.
	 *
	 * @param token   The JWE token to decrypt.
	 * @param key     The decryption key material, which can be a named key, PEM/JWK string, or raw secret. Optional if defaultDecryptionKey is
	 *                configured.
	 * @param options Decryption options such as keyAlgorithm and encAlgorithm.
	 *
	 * @return The decrypted payload as a struct, or a struct containing the raw payload string for nested JWT scenarios.
	 */
	public String encrypt( Object payload, java.security.Key key, IStruct options ) {
		try {
			String				keyAlgStr		= getSetting( options, KeyDictionary.keyAlgorithm,
			    StringCaster.cast( getDefaultSetting( KeyDictionary.defaultKeyAlgorithm, "RSA-OAEP-256" ) ) );
			String				encAlgStr		= getSetting( options, KeyDictionary.encAlgorithm,
			    StringCaster.cast( getDefaultSetting( KeyDictionary.defaultEncAlgorithm, "A256GCM" ) ) );

			JWEAlgorithm		keyAlg			= JWEAlgorithm.parse( keyAlgStr );
			EncryptionMethod	encAlg			= EncryptionMethod.parse( encAlgStr );
			JWEHeader.Builder	headerBuilder	= new JWEHeader.Builder( keyAlg, encAlg );
			applyHeaders( headerBuilder, options );

			JWEEncrypter	encrypter	= createEncrypter( key, keyAlg, encAlg );
			Object			payloadVal	= payload;
			if ( payload instanceof IStruct s ) {
				Map<String, Object> map = new java.util.HashMap<>();
				for ( Map.Entry<Key, Object> entry : s.entrySet() ) {
					map.put( entry.getKey().getName(), entry.getValue() );
				}
				payloadVal = map;
			}
			String		payloadStr	= payloadVal instanceof Map<?, ?> m
			    ? JSONObjectUtils.toJSONString( ( Map<String, ?> ) m )
			    : StringCaster.cast( payloadVal );
			JWEObject	jweObject	= new JWEObject( headerBuilder.build(), new Payload( payloadStr ) );
			jweObject.encrypt( encrypter );
			return jweObject.serialize();
		} catch ( JOSEException e ) {
			throw new JWTEncryptionException( "Failed to encrypt: " + e.getMessage(), e );
		} catch ( Exception e ) {
			throw new JWTParseException( "Failed to encrypt: " + e.getMessage(), e );
		}
	}

	/**
	 * BIF implementation for JWT decryption. Accepts a JWE token, decryption key material, and options to return the decrypted payload.
	 * For structured payloads, this returns a claims struct. For nested JWT scenarios, the returned struct includes the nested payload string for
	 * follow-up verification.
	 *
	 * @param token   The JWE token to decrypt.
	 * @param key     The decryption key material, which can be a named key, PEM/JWK string, or raw secret. Optional if defaultDecryptionKey is
	 *                configured.
	 * @param options Decryption options such as keyAlgorithm and encAlgorithm.
	 *
	 * @return The decrypted payload as a struct, or a struct containing the raw payload string for nested JWT scenarios.
	 */
	public IStruct decrypt( String token, java.security.Key key, IStruct options ) {
		try {
			String				keyAlgStr	= getSetting( options, KeyDictionary.keyAlgorithm,
			    StringCaster.cast( getDefaultSetting( KeyDictionary.defaultKeyAlgorithm, "RSA-OAEP-256" ) ) );
			String				encAlgStr	= getSetting( options, KeyDictionary.encAlgorithm,
			    StringCaster.cast( getDefaultSetting( KeyDictionary.defaultEncAlgorithm, "A256GCM" ) ) );

			JWEAlgorithm		keyAlg		= JWEAlgorithm.parse( keyAlgStr );
			EncryptionMethod	encAlg		= EncryptionMethod.parse( encAlgStr );
			JWEDecrypter		decrypter	= createDecrypter( key, keyAlg, encAlg );
			JWEObject			jweObject	= JWEObject.parse( token );
			jweObject.decrypt( decrypter );
			String payloadStr = jweObject.getPayload().toString();
			try {
				return claimsToStruct( JWTClaimsSet.parse( payloadStr ) );
			} catch ( Exception e ) {
				IStruct result = new Struct();
				result.put( Key.of( "payload" ), payloadStr );
				return result;
			}
		} catch ( JOSEException e ) {
			throw new JWTEncryptionException( "Failed to decrypt: " + e.getMessage(), e );
		} catch ( Exception e ) {
			throw new JWTParseException( "Failed to parse JWE: " + e.getMessage(), e );
		}
	}

	/**
	 * --------------------------------------------------------------------------
	 * Private Helpers
	 * --------------------------------------------------------------------------
	 */

	/**
	 * Creates a JWSSigner based on the provided key and algorithm. Supports RSA, EC, and HMAC keys.
	 *
	 * @param key The key to use for signing.
	 * @param alg The algorithm to use for signing.
	 *
	 * @return A JWSSigner instance.
	 *
	 * @throws JOSEException If an error occurs while creating the signer.
	 */
	private JWSSigner createSigner( java.security.Key key, JWSAlgorithm alg ) throws JOSEException {
		if ( key instanceof ECPrivateKey ecKey ) {
			return new ECDSASigner( ecKey );
		}
		if ( key instanceof RSAPrivateKey rsaKey ) {
			return new RSASSASigner( rsaKey );
		}
		if ( key instanceof SecretKey sk ) {
			return new MACSigner( sk );
		}
		if ( key instanceof PrivateKey pk ) {
			return new RSASSASigner( pk );
		}
		throw new JWTKeyException( "Unsupported key type for signing: " + key.getClass().getName() );
	}

	/**
	 * Create a JWSVerifier based on the provided key and algorithm. Supports RSA, EC, and HMAC keys.
	 *
	 * @param key The key to use for verification.
	 * @param alg The algorithm to use for verification.
	 *
	 * @return A JWSVerifier instance.
	 *
	 * @throws JOSEException If an error occurs while creating the verifier.
	 */
	private JWSVerifier createVerifier( java.security.Key key, JWSAlgorithm alg ) throws JOSEException {

		if ( key instanceof ECPublicKey ecKey ) {
			return new ECDSAVerifier( ecKey );
		}
		if ( key instanceof RSAPublicKey rsaKey ) {
			return new RSASSAVerifier( rsaKey );
		}
		if ( key instanceof SecretKey sk ) {
			return new MACVerifier( sk );
		}
		if ( key instanceof PublicKey pk ) {
			return new RSASSAVerifier( ( RSAPublicKey ) pk );
		}
		throw new JWTKeyException( "Unsupported key type for verification: " + key.getClass().getName() );
	}

	/**
	 * Creates a JWEEncrypter based on the provided key, key algorithm, and encryption method. Supports RSA, EC, and symmetric keys.
	 *
	 * @param key    The key to use for encryption.
	 * @param keyAlg The JWE algorithm to use for key management.
	 * @param encAlg The encryption method to use for content encryption.
	 *
	 * @return A JWEEncrypter instance.
	 *
	 * @throws JOSEException If an error occurs while creating the encrypter.
	 */
	private JWEEncrypter createEncrypter( java.security.Key key, JWEAlgorithm keyAlg, EncryptionMethod encAlg ) throws JOSEException {
		if ( keyAlg.toString().equals( "dir" ) ) {
			return new DirectEncrypter( ( SecretKey ) key );
		}
		if ( key instanceof RSAPublicKey rsaKey ) {
			return new RSAEncrypter( rsaKey );
		}
		if ( key instanceof PublicKey pubKey ) {
			return new RSAEncrypter( ( RSAPublicKey ) pubKey );
		}
		if ( key instanceof SecretKey sk ) {
			return new DirectEncrypter( sk );
		}
		throw new JWTKeyException( "Unsupported key type for encryption: " + key.getClass().getName() );
	}

	/**
	 * Creates a JWEDecrypter based on the provided key, key algorithm, and encryption method. Supports RSA, EC, and symmetric keys.
	 *
	 * @param key    The key to use for decryption.
	 * @param keyAlg The JWE algorithm to use for key management.
	 * @param encAlg The encryption method to use for content encryption.
	 *
	 * @return A JWEDecrypter instance.
	 *
	 * @throws JOSEException If an error occurs while creating the decrypter.
	 */
	private JWEDecrypter createDecrypter( java.security.Key key, JWEAlgorithm keyAlg, EncryptionMethod encAlg ) throws JOSEException {
		if ( keyAlg.toString().equals( "dir" ) ) {
			return new DirectDecrypter( ( SecretKey ) key );
		}
		if ( key instanceof RSAPrivateKey rsaKey ) {
			return new RSADecrypter( rsaKey );
		}
		if ( key instanceof PrivateKey privKey ) {
			return new RSADecrypter( ( RSAPrivateKey ) privKey );
		}
		if ( key instanceof SecretKey sk ) {
			return new DirectDecrypter( sk );
		}
		throw new JWTKeyException( "Unsupported key type for decryption: " + key.getClass().getName() );
	}

	/**
	 * Builds a JWTClaimsSet.Builder from the provided payload struct and options. Handles claim conversion, automatic iat/jti generation, and other
	 * claim-related options.
	 *
	 * @param payload The payload struct containing claims to include in the JWT.
	 * @param options Options that may influence claim generation, such as generateIat and generateJti.
	 *
	 * @return A JWTClaimsSet.Builder populated with the claims from the payload and any additional generated claims.
	 */
	private JWTClaimsSet.Builder buildClaims( IStruct payload, IStruct options ) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Iterate over the payload struct and add each entry as a claim in the JWTClaimsSet.Builder.
		// If a value is a DateTime, we convert it to a java.util.Date for compatibility with the JWTClaimsSet.Builder.
		for ( Map.Entry<Key, Object> entry : payload.entrySet() ) {
			Object value = entry.getValue();
			if ( value instanceof DateTime dt ) {
				value = Date.from( dt.getWrapped().toInstant() );
			}
			builder.claim( entry.getKey().getName(), value );
		}

		// Default Generation Options from Config
		boolean	defaultGenerateIat	= BooleanCaster.cast( getDefaultSetting( KeyDictionary.generateIat, true ) );
		boolean	defaultGenerateJti	= BooleanCaster.cast( getDefaultSetting( KeyDictionary.generateJti, true ) );
		// Get generation options from incoming struct, or defaults.
		boolean	generateIat			= options.containsKey( KeyDictionary.generateIat )
		    ? BooleanCaster.cast( options.get( KeyDictionary.generateIat ) )
		    : defaultGenerateIat;
		boolean	generateJti			= options.containsKey( KeyDictionary.generateJti )
		    ? BooleanCaster.cast( options.get( KeyDictionary.generateJti ) )
		    : defaultGenerateJti;

		if ( generateIat && !payload.containsKey( KeyDictionary.iat ) ) {
			builder.issueTime( new Date() );
		}
		if ( generateJti && !payload.containsKey( KeyDictionary.jti ) ) {
			builder.jwtID( UUID.randomUUID().toString() );
		}

		return builder;
	}

	/**
	 * Applies custom JOSE header parameters from the options struct to the JWSHeader.Builder.
	 *
	 * @param builder The JWSHeader.Builder to apply the headers to.
	 * @param options The options struct that may contain a "headers" struct with custom header parameters.
	 */
	private void applyHeaders( JWSHeader.Builder builder, IStruct options ) {
		if ( options == null ) {
			return;
		}
		Object headersObj = options.get( KeyDictionary.headers );
		if ( headersObj instanceof IStruct headers ) {
			for ( Map.Entry<Key, Object> entry : headers.entrySet() ) {
				String	name	= entry.getKey().getName();
				String	value	= StringCaster.cast( entry.getValue() );
				setHeaderParam( builder, name, value );
			}
		}
	}

	/**
	 * Applies custom JOSE header parameters from the options struct to the JWEHeader.Builder.
	 *
	 * @param builder The JWEHeader.Builder to apply the headers to.
	 * @param options The options struct that may contain a "headers" struct with custom header parameters.
	 */
	private void applyHeaders( JWEHeader.Builder builder, IStruct options ) {
		if ( options == null ) {
			return;
		}
		Object headersObj = options.get( KeyDictionary.headers );
		if ( headersObj instanceof IStruct headers ) {
			for ( Map.Entry<Key, Object> entry : headers.entrySet() ) {
				String	name	= entry.getKey().getName();
				String	value	= StringCaster.cast( entry.getValue() );
				setJweHeaderParam( builder, name, value );
			}
		}
	}

	/**
	 * Sets a header parameter on the JWSHeader.Builder based on the parameter name. Recognizes standard JOSE header fields and sets them using the
	 * appropriate builder methods. Unrecognized fields are added as custom parameters.
	 *
	 * @param builder The JWSHeader.Builder to set the parameter on.
	 * @param name    The name of the header parameter.
	 * @param value   The value of the header parameter.
	 */
	private void setHeaderParam( JWSHeader.Builder builder, String name, String value ) {
		switch ( name ) {
			case "kid" -> builder.keyID( value );
			case "cty" -> builder.contentType( value );
			case "typ" -> builder.type( new com.nimbusds.jose.JOSEObjectType( value ) );
			default -> builder.customParam( name, value );
		}
	}

	/**
	 * Sets a header parameter on the JWEHeader.Builder based on the parameter name. Recognizes standard JOSE header fields and sets them using the
	 * appropriate builder methods. Unrecognized fields are added as custom parameters.
	 *
	 * @param builder The JWEHeader.Builder to set the parameter on.
	 * @param name    The name of the header parameter.
	 * @param value   The value of the header parameter.
	 */
	private void setJweHeaderParam( JWEHeader.Builder builder, String name, String value ) {
		switch ( name ) {
			case "kid" -> builder.keyID( value );
			case "cty" -> builder.contentType( value );
			case "typ" -> builder.type( new com.nimbusds.jose.JOSEObjectType( value ) );
			default -> builder.customParam( name, value );
		}
	}

	/**
	 * Validates the claims in the JWTClaimsSet against expected values and time-based constraints specified in the options. Checks for claim mismatches,
	 * expiration, and not-before conditions, applying any configured clock skew.
	 *
	 * @param claimsSet The JWTClaimsSet to validate.
	 * @param options   The options struct that may contain expected claim values under "claims" and clock skew under "clockSkew".
	 *
	 * @throws JWTVerificationException If any claim validation fails, including mismatched claims, expired tokens, or tokens not yet valid.
	 */
	private void validateClaims( JWTClaimsSet claimsSet, IStruct options ) {
		// Get the expected claims from the options struct, which should be under the "claims" key.
		// This is a struct where each key is a claim name and the value is the expected claim value.
		// Ex: options.claims = { "iss": "my-issuer", "aud": "my-audience" }
		IStruct claims = options.getAsStruct( KeyDictionary.claims );

		// Iterate over the expected claims and compare them to the actual claims in the JWTClaimsSet. If any claim does not match the expected value, throw a
		// JWTVerificationException with details about the mismatch. This allows for flexible claim validation based
		if ( claims != null ) {
			for ( Map.Entry<Key, Object> entry : claims.entrySet() ) {
				String	claimName	= entry.getKey().getName();
				String	expected	= StringCaster.cast( entry.getValue() );
				// aud is always a List<String> in Nimbus regardless of how it was encoded,
				// so check membership rather than equality.
				if ( claimName.equals( "aud" ) ) {
					java.util.List<String> audList = claimsSet.getAudience();
					if ( audList == null || !audList.contains( expected ) ) {
						throw new JWTVerificationException(
						    "Claim \"aud\" mismatch: expected \"" + expected + "\", got \"" + audList + "\"" );
					}
				} else {
					Object actual = claimsSet.getClaim( claimName );
					if ( expected != null && !expected.equals( StringCaster.cast( actual ) ) ) {
						throw new JWTVerificationException(
						    "Claim \"" + claimName + "\" mismatch: expected \"" + expected + "\", got \"" + actual
						        + "\"" );
					}
				}
			}
		}

		// Validate Time-Base Claims (exp, nbf) with Clock Skew

		long clockSkewSeconds = 0;
		// If we have an options clockSkew, use it.
		if ( options.containsKey( KeyDictionary.clockSkew ) ) {
			clockSkewSeconds = LongCaster.cast( options.get( KeyDictionary.clockSkew ) );
		} else {
			// Use the module default
			clockSkewSeconds = LongCaster.cast( getDefaultSetting( KeyDictionary.clockSkew, DEFAULT_CLOCK_SKEW ) );
		}

		// Verify Token Expiration: subtract skew so tokens expired within the window are still accepted
		long	skewMs				= clockSkewSeconds * 1000;
		Date	expCheck			= new Date( System.currentTimeMillis() - skewMs );
		Date	targetExpiration	= claimsSet.getExpirationTime();
		if ( targetExpiration != null && expCheck.after( targetExpiration ) ) {
			throw new JWTExpiredException( "JWT has expired at " + targetExpiration );
		}

		// Verify Not-Before: add skew so tokens that become valid within the window are accepted.
		// This uses the opposite direction from exp — if the issuer's clock is ahead of ours by up
		// to skew seconds, the token should still be accepted.
		Date	nbfCheck	= new Date( System.currentTimeMillis() + skewMs );
		Date	targetNbf	= claimsSet.getNotBeforeTime();
		if ( targetNbf != null && nbfCheck.before( targetNbf ) ) {
			throw new JWTNotYetValidException( "JWT not valid before " + targetNbf );
		}
	}

	/**
	 * Converts a JWTClaimsSet to an IStruct, handling the conversion of Date objects to DateTime for better compatibility with BIF usage. This allows the
	 * claims to be returned in a structured format that can be easily accessed in BIFs while preserving date information.
	 *
	 * @param claimsSet The JWTClaimsSet to convert.
	 *
	 * @return An IStruct containing the claims from the JWTClaimsSet, with Date fields converted to DateTime.
	 */
	private IStruct claimsToStruct( JWTClaimsSet claimsSet ) {
		IStruct result = new Struct();
		for ( Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet() ) {
			String	key	= entry.getKey();
			Object	val	= entry.getValue();
			if ( val instanceof Date date ) {
				result.put( Key.of( key ), new DateTime( date, ZoneId.of( "UTC" ) ) );
			} else {
				result.put( Key.of( key ), val );
			}
		}
		return result;
	}

	/**
	 * Parses a PEM-encoded key string or file path into a java.security.Key object. Supports both private and public keys.
	 *
	 * @param pem       The PEM-encoded key string or file path.
	 * @param isPrivate Indicates whether the key is a private key.
	 *
	 * @return The parsed java.security.Key object.
	 *
	 * @throws JWTKeyException If the key cannot be parsed.
	 */
	private java.security.Key parsePemKey( String pem, boolean isPrivate ) {
		try {
			String pemContent = pem.strip();
			if ( pemContent.startsWith( "-----BEGIN" ) ) {
				return parsePemString( pemContent, isPrivate );
			}
			String fileContent = Files.readString( Paths.get( pemContent ) );
			return parsePemString( fileContent, isPrivate );
		} catch ( Exception e ) {
			throw new JWTKeyException( "Failed to parse PEM key: " + pem + " - " + e.getMessage(), e );
		}
	}

	/**
	 * Parses a PEM-encoded key string into a java.security.Key object. This method is used internally after determining that the input is a PEM string.
	 *
	 * @param pem       The PEM-encoded key string.
	 * @param isPrivate Indicates whether the key is a private key.
	 *
	 * @return The parsed java.security.Key object.
	 *
	 * @throws JWTKeyException If the key cannot be parsed.
	 */
	private java.security.Key parsePemString( String pem, boolean isPrivate ) {
		try {
			String		b64		= pem.replaceAll( "-----[A-Z ]+-----", "" ).replaceAll( "\\s", "" );
			byte[]		decoded	= Base64.getDecoder().decode( b64 );
			KeyFactory	kf;
			if ( isPrivate ) {
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decoded );
				try {
					kf = KeyFactory.getInstance( "RSA" );
					return kf.generatePrivate( spec );
				} catch ( Exception e1 ) {
					try {
						kf = KeyFactory.getInstance( "EC" );
						return kf.generatePrivate( spec );
					} catch ( Exception e2 ) {
						throw new JWTKeyException( "Unsupported private key algorithm: " + e2.getMessage(), e2 );
					}
				}
			} else {
				X509EncodedKeySpec spec = new X509EncodedKeySpec( decoded );
				try {
					kf = KeyFactory.getInstance( "RSA" );
					return kf.generatePublic( spec );
				} catch ( Exception e1 ) {
					try {
						kf = KeyFactory.getInstance( "EC" );
						return kf.generatePublic( spec );
					} catch ( Exception e2 ) {
						throw new JWTKeyException( "Unsupported public key algorithm: " + e2.getMessage(), e2 );
					}
				}
			}
		} catch ( Exception e ) {
			throw new JWTKeyException( "Failed to decode PEM key: " + e.getMessage(), e );
		}
	}

	/**
	 * Parses a raw secret string into a SecretKey for HMAC algorithms. The algorithm parameter determines the specific HMAC variant (e.g., HS256, HS384,
	 * HS512).
	 *
	 * @param secret    The raw secret string to parse.
	 * @param algorithm The HMAC algorithm to use (e.g., "HS256", "HS384", "HS512").
	 *
	 * @return A SecretKey object representing the HMAC secret.
	 *
	 * @throws JWTKeyException If the secret cannot be parsed or if the algorithm is unsupported.
	 */
	private SecretKey parseHmacSecret( String secret, String algorithm ) {
		try {
			String hmacAlg = switch ( algorithm ) {
				case "HS384" -> "HmacSHA384";
				case "HS512" -> "HmacSHA512";
				default -> "HmacSHA256";
			};
			return new SecretKeySpec( secret.getBytes( StandardCharsets.UTF_8 ), hmacAlg );
		} catch ( Exception e ) {
			throw new JWTKeyException( "Failed to create HMAC key: " + e.getMessage(), e );
		}
	}

	/**
	 * Parses a JWK struct into a java.security.Key object. Supports RSA and EC keys, both private and public. The struct should contain the necessary JWK
	 * parameters for the key type.
	 *
	 * @param jwkStruct The struct containing the JWK parameters.
	 *
	 * @return The parsed java.security.Key object.
	 *
	 * @throws JWTKeyException If the JWK cannot be parsed or if the key type is unsupported.
	 */
	private java.security.Key parseJwkStruct( IStruct jwkStruct ) {
		try {
			Map<String, Object> map = new java.util.HashMap<>();
			for ( Map.Entry<Key, Object> entry : jwkStruct.entrySet() ) {
				map.put( entry.getKey().getName(), entry.getValue() );
			}
			JWK jwk = JWK.parse( map );
			if ( jwk instanceof RSAKey rsaKey ) {
				if ( rsaKey.isPrivate() ) {
					return rsaKey.toPrivateKey();
				}
				return rsaKey.toPublicKey();
			}
			if ( jwk instanceof ECKey ecKey ) {
				if ( ecKey.isPrivate() ) {
					return ecKey.toPrivateKey();
				}
				return ecKey.toPublicKey();
			}
			throw new JWTKeyException( "Unsupported JWK type: " + jwk.getKeyType() );
		} catch ( Exception e ) {
			throw new JWTKeyException( "Failed to parse JWK struct: " + e.getMessage(), e );
		}
	}

	/**
	 * Determines if the provided algorithm string corresponds to an HMAC algorithm (e.g., HS256, HS384, HS512). This is used to decide how to parse key
	 * material for
	 * signing and verification.
	 *
	 * @param algorithm The algorithm string to check.
	 *
	 * @return True if the algorithm is an HMAC algorithm, false otherwise.
	 */
	private boolean isHmacAlgorithm( String algorithm ) {
		return algorithm != null && ( algorithm.startsWith( "HS" ) );
	}

	/**
	 * Retrieves a setting value from the options struct, falling back to a default value if the setting is not present.
	 * This is used to determine algorithm choices and other configurable parameters for encryption and verification.
	 *
	 * @param options      The options struct that may contain the setting.
	 * @param key          The key representing the setting to retrieve.
	 * @param defaultValue The default value to return if the setting is not present in the options.
	 *
	 * @return The setting value from the options, or the default value if not present.
	 */
	private String getSetting( IStruct options, Key key, String defaultValue ) {
		if ( options == null || !options.containsKey( key ) ) {
			return defaultValue;
		}
		return StringCaster.cast( options.get( key ) );
	}

	/**
	 * Retrieves a default setting value from the module settings, falling back to a provided default if the setting is not configured. This allows for
	 * module-level
	 * defaults to be defined for algorithm choices and other parameters, which can be overridden in the options passed to the BIFs.
	 *
	 * @param key          The key representing the setting to retrieve.
	 * @param defaultValue The default value to return if the setting is not present in the module settings.
	 *
	 * @return The setting value from the module settings, or the default value if not present.
	 */
	private Object getDefaultSetting( Key key, Object defaultValue ) {
		if ( !MODULE_SETTINGS.containsKey( key ) ) {
			return defaultValue;
		}
		return MODULE_SETTINGS.get( key );
	}

	/**
	 * Parses configured keys from the module settings and registers them in the key registry. This allows keys to be defined in the module configuration
	 * and
	 * accessed by name in the BIFs. The keys should be defined under the "keys" struct in the module settings, with each entry containing the necessary
	 * information to parse the key material (e.g., PEM string, JWK struct, or raw secret).
	 */
	private void parseConfiguredKeys() {
		IStruct keyConfig = MODULE_SETTINGS.getAsStruct( KeyDictionary.keys );
		if ( keyConfig == null || keyConfig.isEmpty() ) {
			return;
		}

		for ( Map.Entry<Key, Object> entry : keyConfig.entrySet() ) {
			String	keyName	= entry.getKey().getName();
			IStruct	keyDef	= StructCaster.cast( entry.getValue() );
			registerKey( keyName, keyDef );
		}
	}

}
