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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.jwt.BaseIntegrationTest;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JwtGenerateKeyPairTest extends BaseIntegrationTest {

	@DisplayName( "jwtGenerateKeyPair RS256 returns PEM strings" )
	@Test
	public void testRs256ReturnsPem() {
		runtime.executeSource(
		    """
		    keys       = jwtGenerateKeyPair( "RS256" );
		    privResult = left( keys.privateKey, 27 );
		    pubResult  = left( keys.publicKey, 26 );
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "privResult" ) ).isEqualTo( "-----BEGIN PRIVATE KEY-----" );
		assertThat( ( String ) variables.get( "pubResult" ) ).isEqualTo( "-----BEGIN PUBLIC KEY-----" );
	}

	@DisplayName( "jwtGenerateKeyPair RS256 keys can sign and verify" )
	@Test
	public void testRs256SignAndVerify() {
		runtime.executeSource(
		    """
		    keys    = jwtGenerateKeyPair( "RS256" );
		    token   = jwtCreate( { sub: "rsa-user", iss: "test" }, keys.privateKey, "RS256" );
		    payload = jwtVerify( token, keys.publicKey, "RS256" );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "rsa-user" );
	}

	@DisplayName( "jwtGenerateKeyPair ES256 keys can sign and verify" )
	@Test
	public void testEs256SignAndVerify() {
		runtime.executeSource(
		    """
		    keys    = jwtGenerateKeyPair( "ES256" );
		    token   = jwtCreate( { sub: "ec-user" }, keys.privateKey, "ES256" );
		    payload = jwtVerify( token, keys.publicKey, "ES256" );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "ec-user" );
	}

	@DisplayName( "jwtGenerateKeyPair defaults to RS256" )
	@Test
	public void testDefaultAlgorithmIsRs256() {
		runtime.executeSource(
		    """
		    keys    = jwtGenerateKeyPair();
		    token   = jwtCreate( { sub: "default-rsa" }, keys.privateKey, "RS256" );
		    payload = jwtVerify( token, keys.publicKey, "RS256" );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "default-rsa" );
	}

	@DisplayName( "jwtGenerateKeyPair throws for unsupported algorithm" )
	@Test
	public void testThrowsForHmacAlgorithm() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    jwtGenerateKeyPair( "HS256" );
		    """,
		    context
		) );
	}

}
