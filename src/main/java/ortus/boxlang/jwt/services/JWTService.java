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
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.services.BaseService;
import ortus.boxlang.runtime.types.Array;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

public class JWTService extends BaseService {

	/**
	 * --------------------------------------------------------------------------
	 * Public Properties
	 * --------------------------------------------------------------------------
	 */

	private ConcurrentHashMap<String, JWTKeyEntry> keyRegistry = new ConcurrentHashMap<>();

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
	}

	/**
	 * Called when the service is shut down. Clears the key registry.
	 *
	 * @param force Whether the shutdown is forced.
	 */
	@Override
	public void onShutdown( Boolean force ) {
		this.keyRegistry.clear();
	}

	/**
	 * --------------------------------------------------------------------------
	 * Methods for JWT Operations and Key Management
	 * --------------------------------------------------------------------------
	 */

	public JWTKeyEntry registerKey( String name, IStruct keyConfig ) {
		String algorithm = StringCaster.cast( keyConfig.getOrDefault( KeyDictionary.algorithm, "" ) );
		if ( algorithm.isEmpty() ) {
			throw new JWTKeyException( "Key \"" + name + "\" is missing required field: algorithm" );
		}

		JWTKeyEntry	entry		= new JWTKeyEntry( name, algorithm );

		Object		secretVal	= keyConfig.get( KeyDictionary.secret );
		if ( secretVal != null ) {
			String secret = interpolateEnvVars( StringCaster.cast( secretVal ) );
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

		keyRegistry.put( name, entry );
		return entry;
	}

	public JWTKeyEntry getKey( String name ) {
		JWTKeyEntry entry = keyRegistry.get( name );
		if ( entry == null ) {
			throw new JWTKeyException( "Key \"" + name + "\" is not registered" );
		}
		return entry;
	}

	public void removeKey( String name ) {
		keyRegistry.remove( name );
	}

	public void clearKeys() {
		keyRegistry.clear();
	}

	public Array getKeyNames() {
		return Array.fromSet( keyRegistry.keySet() );
	}

	public boolean hasKey( String name ) {
		return keyRegistry.containsKey( name );
	}

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

	public java.security.Key parseKey( Object keyArg, String algorithm ) {
		if ( keyArg == null ) {
			throw new JWTKeyException( "Key argument is null. Provide a named key, PEM string, JWK struct, or raw secret." );
		}
		if ( keyArg instanceof java.security.Key jKey ) {
			return jKey;
		}
		String keyStr = StringCaster.cast( keyArg );
		if ( keyStr.contains( "-----BEGIN" ) ) {
			boolean isPrivate = keyStr.contains( "PRIVATE" );
			return parsePemString( keyStr.strip(), isPrivate );
		}
		if ( isHmacAlgorithm( algorithm ) ) {
			return parseHmacSecret( keyStr, algorithm );
		}
		try {
			return parseHmacSecret( keyStr, "HS256" );
		} catch ( Exception e ) {
			return parsePemString( keyStr.strip(), false );
		}
	}

	public String create( IStruct payload, java.security.Key key, String algorithm, IStruct options ) {
		try {
			JWSAlgorithm			alg				= JWSAlgorithm.parse( algorithm );
			JWSSigner				signer			= createSigner( key, alg );
			JWTClaimsSet.Builder	claimsBuilder	= buildClaims( payload, options );
			JWSHeader.Builder		headerBuilder	= new JWSHeader.Builder( alg );
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

	public IStruct verify( String token, java.security.Key key, String algorithm, IStruct options ) {
		try {
			JWSAlgorithm	alg			= JWSAlgorithm.parse( algorithm );
			SignedJWT		signedJWT	= SignedJWT.parse( token );
			JWSVerifier		verifier	= createVerifier( key, alg );
			if ( !signedJWT.verify( verifier ) ) {
				throw new JWTVerificationException( "JWT signature verification failed" );
			}
			JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
			validateClaims( claimsSet, options );
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

	private JWSSigner createSigner( java.security.Key key, JWSAlgorithm alg ) throws JOSEException {
		if ( key instanceof RSAPrivateKey || key instanceof ECPrivateKey ) {
			if ( alg.toString().startsWith( "ES" ) || alg.toString().equals( "EdDSA" ) ) {
				return new ECDSASigner( ( ECPrivateKey ) key );
			}
			return new RSASSASigner( ( PrivateKey ) key );
		}
		if ( key instanceof SecretKey sk ) {
			return new MACSigner( sk );
		}
		if ( key instanceof PrivateKey pk ) {
			return new RSASSASigner( pk );
		}
		throw new JWTKeyException( "Unsupported key type for signing: " + key.getClass().getName() );
	}

	private JWSVerifier createVerifier( java.security.Key key, JWSAlgorithm alg ) throws JOSEException {
		if ( key instanceof RSAPublicKey || key instanceof ECPublicKey ) {
			if ( alg.toString().startsWith( "ES" ) || alg.toString().equals( "EdDSA" ) ) {
				return new ECDSAVerifier( ( ECPublicKey ) key );
			}
			return new RSASSAVerifier( ( RSAPublicKey ) key );
		}
		if ( key instanceof SecretKey sk ) {
			return new MACVerifier( sk );
		}
		if ( key instanceof PublicKey pk ) {
			return new RSASSAVerifier( ( RSAPublicKey ) pk );
		}
		throw new JWTKeyException( "Unsupported key type for verification: " + key.getClass().getName() );
	}

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

	private JWTClaimsSet.Builder buildClaims( IStruct payload, IStruct options ) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		for ( Map.Entry<Key, Object> entry : payload.entrySet() ) {
			Object value = entry.getValue();
			if ( value instanceof DateTime dt ) {
				value = Date.from( dt.getWrapped().toInstant() );
			}
			builder.claim( entry.getKey().getName(), value );
		}
		boolean	generateIat			= options != null && options.containsKey( KeyDictionary.generateIat )
		    && Boolean.TRUE.equals( options.get( KeyDictionary.generateIat ) );
		boolean	generateJti			= options != null && options.containsKey( KeyDictionary.generateJti )
		    && Boolean.TRUE.equals( options.get( KeyDictionary.generateJti ) );

		boolean	defaultGenerateIat	= Boolean.TRUE.equals( getDefaultSetting( KeyDictionary.generateIat, true ) );
		boolean	defaultGenerateJti	= Boolean.TRUE.equals( getDefaultSetting( KeyDictionary.generateJti, false ) );

		if ( generateIat
		    || ( options != null && !options.containsKey( KeyDictionary.generateIat ) && defaultGenerateIat ) ) {
			builder.issueTime( new Date() );
		}
		if ( generateJti
		    || ( options != null && !options.containsKey( KeyDictionary.generateJti ) && defaultGenerateJti ) ) {
			builder.jwtID( UUID.randomUUID().toString() );
		}
		return builder;
	}

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

	private void setHeaderParam( JWSHeader.Builder builder, String name, String value ) {
		switch ( name ) {
			case "kid" -> builder.keyID( value );
			case "cty" -> builder.contentType( value );
			case "typ" -> builder.type( new com.nimbusds.jose.JOSEObjectType( value ) );
			default -> builder.customParam( name, value );
		}
	}

	private void setJweHeaderParam( JWEHeader.Builder builder, String name, String value ) {
		switch ( name ) {
			case "kid" -> builder.keyID( value );
			case "cty" -> builder.contentType( value );
			case "typ" -> builder.type( new com.nimbusds.jose.JOSEObjectType( value ) );
			default -> builder.customParam( name, value );
		}
	}

	private void validateClaims( JWTClaimsSet claimsSet, IStruct options ) {
		Object claimsObj = options != null ? options.get( KeyDictionary.claims ) : null;
		if ( claimsObj instanceof IStruct claims ) {
			for ( Map.Entry<Key, Object> entry : claims.entrySet() ) {
				String	claimName	= entry.getKey().getName();
				Object	expected	= entry.getValue();
				Object	actual		= claimsSet.getClaim( claimName );
				if ( expected != null && !expected.equals( actual ) ) {
					throw new JWTVerificationException(
					    "Claim \"" + claimName + "\" mismatch: expected \"" + expected + "\", got \"" + actual
					        + "\"" );
				}
			}
		}
		long clockSkewSeconds = 0;
		if ( options != null ) {
			Object skewObj = options.get( KeyDictionary.clockSkew );
			if ( skewObj instanceof Number num ) {
				clockSkewSeconds = num.longValue();
			}
		}
		Date	now	= new Date( System.currentTimeMillis() - clockSkewSeconds * 1000 );
		Date	exp	= claimsSet.getExpirationTime();
		if ( exp != null && now.after( exp ) ) {
			throw new JWTExpiredException( "JWT has expired at " + exp );
		}
		Date nbf = claimsSet.getNotBeforeTime();
		if ( nbf != null && now.before( nbf ) ) {
			throw new JWTNotYetValidException( "JWT not valid before " + nbf );
		}
	}

	private IStruct claimsToStruct( JWTClaimsSet claimsSet ) {
		IStruct result = new Struct();
		for ( Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet() ) {
			String	key	= entry.getKey();
			Object	val	= entry.getValue();
			if ( val instanceof Date date ) {
				result.put( Key.of( key ), new DateTime( date, ZoneId.systemDefault() ) );
			} else {
				result.put( Key.of( key ), val );
			}
		}
		return result;
	}

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

	private SecretKey parseHmacSecret( String secret, String algorithm ) {
		try {
			String hmacAlg = switch ( algorithm ) {
				case "HS384" -> "HmacSHA384";
				case "HS512" -> "HmacSHA512";
				default -> "HmacSHA256";
			};
			return new SecretKeySpec( secret.getBytes(), hmacAlg );
		} catch ( Exception e ) {
			throw new JWTKeyException( "Failed to create HMAC key: " + e.getMessage(), e );
		}
	}

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

	private String interpolateEnvVars( String value ) {
		if ( value == null || !value.contains( "${" ) ) {
			return value;
		}
		java.util.regex.Matcher	m	= java.util.regex.Pattern.compile( "\\$\\{env\\.([^}]+)\\}" ).matcher( value );
		StringBuffer			sb	= new StringBuffer();
		while ( m.find() ) {
			String	envName	= m.group( 1 );
			String	envVal	= System.getenv( envName );
			m.appendReplacement( sb, envVal != null ? java.util.regex.Matcher.quoteReplacement( envVal ) : "" );
		}
		m.appendTail( sb );
		return sb.toString();
	}

	private boolean isHmacAlgorithm( String algorithm ) {
		return algorithm != null && ( algorithm.startsWith( "HS" ) );
	}

	private String getSetting( IStruct options, Key key, String defaultValue ) {
		if ( options == null || !options.containsKey( key ) ) {
			return defaultValue;
		}
		return StringCaster.cast( options.get( key ) );
	}

	private Object getDefaultSetting( Key key, Object defaultValue ) {
		if ( !runtime.getModuleService().hasModule( KeyDictionary.moduleName ) ) {
			return defaultValue;
		}
		IStruct settings = runtime.getModuleService().getModuleSettings( KeyDictionary.moduleName );
		if ( settings == null || !settings.containsKey( key ) ) {
			return defaultValue;
		}
		return settings.get( key );
	}

	private void parseConfiguredKeys() {
		if ( !runtime.getModuleService().hasModule( KeyDictionary.moduleName ) ) {
			return;
		}
		IStruct settings = runtime.getModuleService().getModuleSettings( KeyDictionary.moduleName );
		if ( settings == null ) {
			return;
		}
		Object keysObj = settings.get( KeyDictionary.keys );
		if ( keysObj == null ) {
			return;
		}
		IStruct keysConfig = StructCaster.cast( keysObj );
		if ( keysConfig.isEmpty() ) {
			return;
		}
		for ( Map.Entry<Key, Object> entry : keysConfig.entrySet() ) {
			String	keyName	= entry.getKey().getName();
			IStruct	keyDef	= StructCaster.cast( entry.getValue() );
			registerKey( keyName, keyDef );
		}
	}

}
