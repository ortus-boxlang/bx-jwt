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

public class JwtEncryptTest extends BaseIntegrationTest {

	private String generateRsaPem( KeyPair pair, boolean isPrivate ) {
		byte[]	encoded	= isPrivate ? pair.getPrivate().getEncoded() : pair.getPublic().getEncoded();
		String	type	= isPrivate ? "PRIVATE KEY" : "PUBLIC KEY";
		String	b64		= Base64.getEncoder().encodeToString( encoded );
		return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
	}

	@DisplayName( "Encrypts and decrypts with direct symmetric key" )
	@Test
	public void testDirectEncrypt() {
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

	@DisplayName( "Encrypts and decrypts with RSA key pair" )
	@Test
	public void testRsaEncrypt() throws Exception {
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

	@DisplayName( "Encrypts a nested signed JWT payload" )
	@Test
	public void testEncryptNestedPayload() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    signed = jwtCreate( { sub: "nestedUser" }, secret, "HS256" );
		    nested = jwtEncrypt( signed, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
		    decrypted = jwtDecrypt( nested, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
		    payload = jwtVerify( decrypted.payload, secret, "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "nestedUser" );
	}

	@DisplayName( "Missing key throws JWTKeyException" )
	@Test
	public void testMissingKeyThrowsException() {
		runtime.executeSource(
		    """
		    result = "";
		    try {
		        jwtEncrypt( { sub: "no-key" } );
		        result = "no-error";
		        } catch ( "bxjwt.JWTKeyException" e ) {
		            result = "missing-key";
		        }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "missing-key" );
	}

}
