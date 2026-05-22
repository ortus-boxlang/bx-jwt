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

import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.jwt.BaseIntegrationTest;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JwtGenerateSecretTest extends BaseIntegrationTest {

	@DisplayName( "jwtGenerateSecret returns a 256-bit Base64 string by default" )
	@Test
	public void testDefaultIs256Bits() {
		runtime.executeSource(
		    """
		    result = jwtGenerateSecret();
		    """,
		    context
		);
		String secret = ( String ) variables.get( "result" );
		assertThat( secret ).isNotEmpty();
		byte[] decoded = Base64.getDecoder().decode( secret );
		assertThat( decoded.length ).isEqualTo( 32 ); // 256 bits = 32 bytes
	}

	@DisplayName( "jwtGenerateSecret returns correct byte length for explicit bits" )
	@Test
	public void testExplicitBits512() {
		runtime.executeSource(
		    """
		    result = jwtGenerateSecret( 512 );
		    """,
		    context
		);
		String secret = ( String ) variables.get( "result" );
		byte[] decoded = Base64.getDecoder().decode( secret );
		assertThat( decoded.length ).isEqualTo( 64 ); // 512 bits = 64 bytes
	}

	@DisplayName( "jwtGenerateSecret with 384 bits returns 48 bytes" )
	@Test
	public void testExplicitBits384() {
		runtime.executeSource(
		    """
		    result = jwtGenerateSecret( 384 );
		    """,
		    context
		);
		String secret = ( String ) variables.get( "result" );
		byte[] decoded = Base64.getDecoder().decode( secret );
		assertThat( decoded.length ).isEqualTo( 48 ); // 384 bits = 48 bytes
	}

	@DisplayName( "jwtGenerateSecret produces different values each call" )
	@Test
	public void testSecretIsRandom() {
		runtime.executeSource(
		    """
		    result  = jwtGenerateSecret();
		    result2 = jwtGenerateSecret();
		    """,
		    context
		);
		String s1 = ( String ) variables.get( "result" );
		String s2 = ( String ) variables.get( "result2" );
		assertThat( s1 ).isNotEqualTo( s2 );
	}

	@DisplayName( "jwtGenerateSecret secret can be used to sign and verify" )
	@Test
	public void testGeneratedSecretIsUsable() {
		runtime.executeSource(
		    """
		    secret  = jwtGenerateSecret( 256 );
		    token   = jwtCreate( { sub: "gen-test" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "gen-test" );
	}

	@DisplayName( "jwtGenerateSecret throws for bits below 128" )
	@Test
	public void testThrowsForTooFewBits() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    jwtGenerateSecret( 64 );
		    """,
		    context
		) );
	}

	@DisplayName( "jwtGenerateSecret throws for bits not multiple of 8" )
	@Test
	public void testThrowsForNonMultipleOf8() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    jwtGenerateSecret( 255 );
		    """,
		    context
		) );
	}

}
