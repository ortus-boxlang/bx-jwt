/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */

package ortus.boxlang.jwt.bifs;

import static com.google.common.truth.Truth.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.jwt.BaseIntegrationTest;
import ortus.boxlang.runtime.scopes.Key;

public class JwtCreateTest extends BaseIntegrationTest {

	private String generateRsaPem( KeyPair pair, boolean isPrivate ) {
		byte[]	encoded	= isPrivate ? pair.getPrivate().getEncoded() : pair.getPublic().getEncoded();
		String	type	= isPrivate ? "PRIVATE KEY" : "PUBLIC KEY";
		String	b64		= Base64.getEncoder().encodeToString( encoded );
		return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
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

	@DisplayName( "Missing key throws JWTKeyException" )
	@Test
	public void testMissingKeyThrowsException() {
		runtime.executeSource(
		    """
		    result = "";
		    try {
		        jwtCreate( { sub: "no-key" } );
		        result = "no-error";
		        } catch ( "bxjwt.JWTKeyException" e ) {
		            result = "missing-key";
		        }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "missing-key" );
	}

	@DisplayName( "iat is auto-generated when not in payload" )
	@Test
	public void testIatAutoGenerated() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result  = structKeyExists( payload, "iat" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "Explicit iat in payload is preserved when generateIat is true" )
	@Test
	public void testExplicitIatIsPreserved() {
		runtime.executeSource(
		    """
		    secret      = "12345678901234567890123456789012";
		    explicitIat = dateAdd( "d", -1, now() );
		    token       = jwtCreate( { sub: "user", iat: explicitIat }, secret, "HS256" );
		    payload     = jwtVerify( token, secret, "HS256" );
		    result      = dateCompare( payload.iat, explicitIat, "s" );
		    """,
		    context
		);
		assertThat( ( Number ) variables.get( "result" ) ).isEqualTo( 0 );
	}

	@DisplayName( "jti is auto-generated when not in payload" )
	@Test
	public void testJtiAutoGenerated() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user" }, secret, "HS256", { generateJti: true } );
		    payload = jwtVerify( token, secret, "HS256" );
		    result  = len( payload.jti ) > 0;
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "Explicit jti in payload is preserved when generateJti is true" )
	@Test
	public void testExplicitJtiIsPreserved() {
		runtime.executeSource(
		    """
		    secret      = "12345678901234567890123456789012";
		    explicitJti = "my-custom-jti-value";
		    token       = jwtCreate( { sub: "user", jti: explicitJti }, secret, "HS256", { generateJti: true } );
		    payload     = jwtVerify( token, secret, "HS256" );
		    result      = payload.jti;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "my-custom-jti-value" );
	}

}
