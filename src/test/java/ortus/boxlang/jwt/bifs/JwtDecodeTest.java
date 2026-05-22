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

public class JwtDecodeTest extends BaseIntegrationTest {

	private static final String SECRET = "12345678901234567890123456789012";

	@DisplayName( "jwtDecode returns header and payload structs" )
	@Test
	public void testDecodeReturnsHeaderAndPayload() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "alice", iss: "myapp" }, secret, "HS256" );
		    decoded = jwtDecode( token );
		    result  = decoded.payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "alice" );
	}

	@DisplayName( "jwtDecode returns alg in header" )
	@Test
	public void testDecodeHeaderContainsAlg() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "test" }, secret, "HS256" );
		    decoded = jwtDecode( token );
		    result  = decoded.header.alg;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "HS256" );
	}

	@DisplayName( "jwtDecode returns custom header fields like kid" )
	@Test
	public void testDecodeHeaderKid() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "test" }, secret, "HS256", { headers: { kid: "v2" } } );
		    decoded = jwtDecode( token );
		    result  = decoded.header.kid;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "v2" );
	}

	@DisplayName( "jwtDecode does not verify the signature" )
	@Test
	public void testDecodeDoesNotVerifySignature() {
		// Decode succeeds even with the wrong secret — no verification is performed
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "bob" }, secret, "HS256" );
		    decoded = jwtDecode( token );
		    result  = decoded.payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "bob" );
	}

	@DisplayName( "jwtDecode throws on malformed token" )
	@Test
	public void testDecodeThrowsOnGarbage() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    jwtDecode( "not.a.jwt.at.all.garbage" );
		    """,
		    context
		) );
	}

}
