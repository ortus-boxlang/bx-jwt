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

public class JwtVerifyTest extends BaseIntegrationTest {

	@DisplayName( "Verifies a valid HMAC token" )
	@Test
	public void testVerifyValidHmacToken() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtCreate( { sub: "verifyUser" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "verifyUser" );
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

	@DisplayName( "Claims validation mismatch throws JWTVerificationException" )
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

	@DisplayName( "Missing key throws JWTKeyException" )
	@Test
	public void testMissingKeyThrowsException() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtCreate( { sub: "verifyUser" }, secret, "HS256" );
		    result = "";
		    try {
		        jwtVerify( token );
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
