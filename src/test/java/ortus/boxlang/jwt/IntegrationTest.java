/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */

/**
 * Integration tests covering all bx-jwt BIFs: sign/verify (HMAC, RSA),
 * encrypt/decrypt (direct, RSA), key registry, builder API, nested JWT,
 * and exception scenarios.
 */
package ortus.boxlang.jwt;

import static com.google.common.truth.Truth.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.runtime.scopes.Key;

public class IntegrationTest extends BaseIntegrationTest {

	private String generateRsaPem( KeyPair pair, boolean isPrivate ) {
		byte[]	encoded	= isPrivate ? pair.getPrivate().getEncoded() : pair.getPublic().getEncoded();
		String	type	= isPrivate ? "PRIVATE KEY" : "PUBLIC KEY";
		String	b64		= Base64.getEncoder().encodeToString( encoded );
		return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
	}

	@DisplayName( "Test the module loads in BoxLang" )
	@Test
	public void testModuleLoads() {
		assertThat( moduleService.getRegistry().containsKey( moduleName ) ).isTrue();
		assertThat( runtime.getGlobalService( "JWTService" ) ).isNotNull();
	}

	@DisplayName( "HMAC sign and verify" )
	@Test
	public void testHmacSignAndVerify() {
		runtime.executeSource(
		    """
		    secret = "my-secret-key-for-testing-32bytes";
		    token = jwtCreate( { sub: "user1", iss: "myapp" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "user1" );
	}

	@DisplayName( "RSA sign and verify" )
	@Test
	public void testRsaSignAndVerify() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance( "RSA" );
		gen.initialize( 2048 );
		KeyPair	pair	= gen.generateKeyPair();
		String	privPem	= generateRsaPem( pair, true );
		String	pubPem	= generateRsaPem( pair, false );

		variables.put( Key.of( "privateKey" ), privPem );
		variables.put( Key.of( "publicKey" ), pubPem );

		runtime.executeSource(
		    """
		    privateKey = variables.privateKey;
		    publicKey = variables.publicKey;

		    token = jwtCreate( { sub: "rsaUser", iss: "myapp" }, privateKey, "RS256" );
		    payload = jwtVerify( token, publicKey, "RS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "rsaUser" );
	}

	@DisplayName( "JWE encrypt and decrypt with direct symmetric key" )
	@Test
	public void testJweDirectEncryptDecrypt() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtEncrypt(
		        { sub: "encryptedUser", pii: "sensitive" },
		        secret,
		        { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
		    );
		    payload = jwtDecrypt(
		        token,
		        secret,
		        { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
		    );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "encryptedUser" );
	}

	@DisplayName( "JWE encrypt and decrypt with RSA" )
	@Test
	public void testJweRsaEncryptDecrypt() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance( "RSA" );
		gen.initialize( 2048 );
		KeyPair	pair	= gen.generateKeyPair();
		String	privPem	= generateRsaPem( pair, true );
		String	pubPem	= generateRsaPem( pair, false );

		variables.put( Key.of( "privateKey" ), privPem );
		variables.put( Key.of( "publicKey" ), pubPem );

		runtime.executeSource(
		    """
		    privateKey = variables.privateKey;
		    publicKey = variables.publicKey;

		    token = jwtEncrypt(
		        { sub: "jweRsaUser" },
		        publicKey,
		        { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" }
		    );
		    payload = jwtDecrypt(
		        token,
		        privateKey,
		        { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" }
		    );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "jweRsaUser" );
	}

	@DisplayName( "Expired token throws JWTExpiredException" )
	@Test
	public void testExpiredToken() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    result = "";
		    try {
		        token = jwtCreate(
		            { sub: "expUser", exp: dateAdd( "s", -60, now() ) },
		            secret,
		            "HS256"
		        );
		        jwtVerify( token, secret, "HS256" );
		        result = "no-error";
		        } catch ( "bxjwt.JWTExpiredException" e ) {
		            result = "expired";
		        }
		        """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "expired" );
	}

	@DisplayName( "Invalid signature throws JWTVerificationException" )
	@Test
	public void testInvalidSignature() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    wrong   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
		    result = "";
		    try {
		        token = jwtCreate( { sub: "valid" }, secret, "HS256" );
		        jwtVerify( token, wrong, "HS256" );
		        result = "no-error";
		        } catch ( "bxjwt.JWTVerificationException" e ) {
		            result = "invalid";
		        }
		        """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "invalid" );
	}

	@DisplayName( "Claims validation" )
	@Test
	public void testClaimsValidation() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtCreate( { sub: "user1", iss: "myapp", aud: "api" }, secret, "HS256" );
		    result = "";
		    try {
		        jwtVerify( token, secret, "HS256", { claims: { iss: "wrong-issuer" } } );
		        result = "no-error";
		        } catch ( "bxjwt.JWTVerificationException" e ) {
		            result = "claim-mismatch";
		        }
		        """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "claim-mismatch" );
	}

	@DisplayName( "jwtNew builder creates signed JWT" )
	@Test
	public void testJwtNewBuilderSign() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtNew()
		        .subject( "builderUser" )
		        .issuer( "builderApp" )
		        .claim( "roles", [ "admin" ] )
		        .header( "kid", "v1" )
		        .sign( secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "builderUser" );
	}

	@DisplayName( "jwtNew builder creates encrypted JWT" )
	@Test
	public void testJwtNewBuilderEncrypt() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtNew()
		        .subject( "builderEncUser" )
		        .claim( "ssn", "123-45-6789" )
		        .encrypt( secret, "dir", "A256GCM" );
		    payload = jwtDecrypt( token, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "builderEncUser" );
	}

	@DisplayName( "Nested JWT: sign then encrypt" )
	@Test
	public void testNestedJwt() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance( "RSA" );
		gen.initialize( 2048 );
		KeyPair	innerPair	= gen.generateKeyPair();
		KeyPair	outerPair	= gen.generateKeyPair();
		String	innerPriv	= generateRsaPem( innerPair, true );
		String	innerPub	= generateRsaPem( innerPair, false );
		String	outerPriv	= generateRsaPem( outerPair, true );
		String	outerPub	= generateRsaPem( outerPair, false );

		variables.put( Key.of( "innerPriv" ), innerPriv );
		variables.put( Key.of( "innerPub" ), innerPub );
		variables.put( Key.of( "outerPriv" ), outerPriv );
		variables.put( Key.of( "outerPub" ), outerPub );

		runtime.executeSource(
		    """
		    innerPriv = variables.innerPriv;
		    innerPub  = variables.innerPub;
		    outerPriv = variables.outerPriv;
		    outerPub  = variables.outerPub;

		    signed = jwtCreate( { sub: "nested", role: "admin" }, innerPriv, "RS256" );
		    nested = jwtEncrypt(
		        signed,
		        outerPub,
		        { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM", headers: { cty: "JWT" } }
		    );
		    decrypted = jwtDecrypt( nested, outerPriv, { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" } );
		    payload   = jwtVerify( decrypted.payload, innerPub, "RS256" );
		    result    = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "nested" );
	}

	@DisplayName( "Key registry: register, list, and use named keys" )
	@Test
	public void testKeyRegistry() {
		runtime.executeSource(
		    """
		    jwtService = getBoxContext().getRuntime().getGlobalService( "JWTService" );
		    jwtService.registerKey(
		        "test-hmac",
		        { algorithm: "HS256", secret: "12345678901234567890123456789012" }
		    );
		    hasKey  = jwtService.hasKey( "test-hmac" );
		    names   = jwtService.getKeyNames();

		    token   = jwtCreate( { sub: "namedKeyUser" }, "test-hmac" );
		    payload = jwtVerify( token, "test-hmac" );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "hasKey" ) ).isTrue();
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "namedKeyUser" );
	}

	@DisplayName( "Key registry: remove key" )
	@Test
	public void testKeyRegistryRemove() {
		runtime.executeSource(
		    """
		    jwtService = getBoxContext().getRuntime().getGlobalService( "JWTService" );
		    jwtService.registerKey(
		        "temp-key",
		        { algorithm: "HS256", secret: "abcdefghijklmnopqrstuvwxyz12345" }
		    );
		    hadKey = jwtService.hasKey( "temp-key" );
		    jwtService.removeKey( "temp-key" );
		    hasKeyAfterRemove = jwtService.hasKey( "temp-key" );
		    result = hadKey && !hasKeyAfterRemove;
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "Default algorithm fallback" )
	@Test
	public void testDefaultAlgorithmFallback() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "defaultAlgo" }, secret );
		    payload = jwtVerify( token, secret );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "defaultAlgo" );
	}

	@DisplayName( "Different HMAC algorithms: HS384, HS512" )
	@Test
	public void testHmacAlgorithms() {
		runtime.executeSource(
		    """
		    secret  = "1234567890123456789012345678901234567890123456789012345678901234";
		    token384 = jwtCreate( { sub: "hs384" }, secret, "HS384" );
		    payload384 = jwtVerify( token384, secret, "HS384" );

		    token512 = jwtCreate( { sub: "hs512" }, secret, "HS512" );
		    payload512 = jwtVerify( token512, secret, "HS512" );

		    result = payload384.sub & ":" & payload512.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "hs384:hs512" );
	}

}
