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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.jwt.BaseIntegrationTest;

public class JwtValidateTest extends BaseIntegrationTest {

	@DisplayName( "jwtValidate returns true for a valid token" )
	@Test
	public void testValidateReturnsTrueForValidToken() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token  = jwtCreate( { sub: "user1" }, secret, "HS256" );
		    result = jwtValidate( token, secret, "HS256" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "jwtValidate returns false for a tampered token" )
	@Test
	public void testValidateReturnsFalseForTamperedToken() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user1" }, secret, "HS256" );
		    // Replace last char to corrupt the signature
		    tampered = left( token, len( token ) - 1 ) & ( right( token, 1 ) == "A" ? "B" : "A" );
		    result   = jwtValidate( tampered, secret, "HS256" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isFalse();
	}

	@DisplayName( "jwtValidate returns false for a wrong secret" )
	@Test
	public void testValidateReturnsFalseForWrongSecret() {
		runtime.executeSource(
		    """
		    secret      = "12345678901234567890123456789012";
		    wrongSecret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
		    token  = jwtCreate( { sub: "user1" }, secret, "HS256" );
		    result = jwtValidate( token, wrongSecret, "HS256" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isFalse();
	}

	@DisplayName( "jwtValidate returns false for an expired token" )
	@Test
	public void testValidateReturnsFalseForExpiredToken() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token  = jwtCreate( { sub: "user1", exp: dateAdd( "s", -10, now() ) }, secret, "HS256" );
		    result = jwtValidate( token, secret, "HS256", { clockSkew: 0 } );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isFalse();
	}

	@DisplayName( "jwtValidate returns false for a garbage string" )
	@Test
	public void testValidateReturnsFalseForGarbage() {
		runtime.executeSource(
		    """
		    result = jwtValidate( "not-a-jwt", "12345678901234567890123456789012", "HS256" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isFalse();
	}

}
