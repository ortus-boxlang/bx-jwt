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

public class JwtDecryptTest extends BaseIntegrationTest {

	private String generateRsaPem( KeyPair pair, boolean isPrivate ) {
		byte[]	encoded	= isPrivate ? pair.getPrivate().getEncoded() : pair.getPublic().getEncoded();
		String	type	= isPrivate ? "PRIVATE KEY" : "PUBLIC KEY";
		String	b64		= Base64.getEncoder().encodeToString( encoded );
		return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
	}

	@DisplayName( "Decrypts direct symmetric JWE" )
	@Test
	public void testDirectDecrypt() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtEncrypt(
		        { sub: "decryptUser" },
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
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "decryptUser" );
	}

	@DisplayName( "Decrypts RSA JWE" )
	@Test
	public void testRsaDecrypt() throws Exception {
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

	@DisplayName( "Decrypt with wrong key throws JWTEncryptionException" )
	@Test
	public void testDecryptWithWrongKey() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    wrong = "abcdefghijklmnopqrstuvwxyz123456";
		    token = jwtEncrypt(
		        { sub: "decryptUser" },
		        secret,
		        { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
		    );
		    result = "";
		    try {
		        jwtDecrypt( token, wrong, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
		        result = "no-error";
		        } catch ( "bxjwt.JWTEncryptionException" e ) {
		            result = "wrong-key";
		        }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "wrong-key" );
	}

	@DisplayName( "Missing key throws JWTKeyException" )
	@Test
	public void testMissingKeyThrowsException() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtEncrypt(
		        { sub: "decryptUser" },
		        secret,
		        { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
		    );
		    result = "";
		    try {
		        jwtDecrypt( token );
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
