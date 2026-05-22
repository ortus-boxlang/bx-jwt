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

	@DisplayName( "aud claim as string is validated correctly" )
	@Test
	public void testAudClaimString() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user", aud: "api" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256", { claims: { aud: "api" } } );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "user" );
	}

	@DisplayName( "aud claim as array member is validated correctly" )
	@Test
	public void testAudClaimArray() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user", aud: [ "api", "mobile" ] }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256", { claims: { aud: "mobile" } } );
		    result  = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "user" );
	}

	@DisplayName( "aud claim mismatch throws JWTVerificationException" )
	@Test
	public void testAudClaimMismatch() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token  = jwtCreate( { sub: "user", aud: "api" }, secret, "HS256" );
		    result = "";
		    try {
		        jwtVerify( token, secret, "HS256", { claims: { aud: "wrong" } } );
		        result = "no-error";
		    } catch ( "bxjwt.JWTVerificationException" e ) {
		        result = "aud-mismatch";
		    }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "aud-mismatch" );
	}

	@DisplayName( "Date claims are returned in UTC" )
	@Test
	public void testDateClaimsReturnedInUtc() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtCreate( { sub: "user" }, secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result  = payload.iat.getWrapped().getZone().getId();
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "UTC" );
	}

	@DisplayName( "nbf in the past is accepted" )
	@Test
	public void testNbfInPastIsAccepted() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtCreate(
		        { sub: "nbfUser", nbf: dateAdd( "s", -30, now() ) },
		        secret,
		        "HS256",
		        { generateIat: false }
		    );
		    payload = jwtVerify( token, secret, "HS256", { clockSkew: 0 } );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "nbfUser" );
	}

	@DisplayName( "nbf too far in future throws JWTNotYetValidException" )
	@Test
	public void testNbfFutureThrowsException() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    result = "";
		    try {
		        token = jwtCreate(
		            { sub: "nbfUser", nbf: dateAdd( "s", 120, now() ) },
		            secret,
		            "HS256",
		            { generateIat: false }
		        );
		        jwtVerify( token, secret, "HS256", { clockSkew: 60 } );
		        result = "no-error";
		    } catch ( "bxjwt.JWTNotYetValidException" e ) {
		        result = "not-yet-valid";
		    }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "not-yet-valid" );
	}

	@DisplayName( "nbf within clock skew window is accepted" )
	@Test
	public void testNbfWithinClockSkewIsAccepted() {
		// Token becomes valid in 30 seconds, but our clock skew is 60 seconds.
		// The issuer's clock may be 30 seconds ahead of ours, so we accept it.
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    result = "";
		    try {
		        token = jwtCreate(
		            { sub: "nbfUser", nbf: dateAdd( "s", 30, now() ) },
		            secret,
		            "HS256",
		            { generateIat: false }
		        );
		        payload = jwtVerify( token, secret, "HS256", { clockSkew: 60 } );
		        result = payload.sub;
		    } catch ( "bxjwt.JWTNotYetValidException" e ) {
		        result = "not-yet-valid";
		    }
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "nbfUser" );
	}

}
