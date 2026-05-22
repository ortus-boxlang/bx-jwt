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

public class JwtRefreshTest extends BaseIntegrationTest {

	@DisplayName( "jwtRefresh returns a new valid token with original claims preserved" )
	@Test
	public void testRefreshPreservesClaims() {
		runtime.executeSource(
		    """
		    secret   = "12345678901234567890123456789012";
		    original = jwtCreate( { sub: "refresh-user", role: "admin" }, secret, "HS256" );
		    newToken = jwtRefresh( original, secret, "HS256" );
		    payload  = jwtVerify( newToken, secret, "HS256" );
		    result   = payload.sub & ":" & payload.role;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "refresh-user:admin" );
	}

	@DisplayName( "jwtRefresh produces a different token string" )
	@Test
	public void testRefreshProducesDifferentToken() {
		runtime.executeSource(
		    """
		    secret   = "12345678901234567890123456789012";
		    original = jwtCreate( { sub: "u1" }, secret, "HS256" );
		    newToken = jwtRefresh( original, secret, "HS256" );
		    result   = ( original != newToken );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "jwtRefresh refreshed token carries a new jti" )
	@Test
	public void testRefreshGeneratesNewJti() {
		runtime.executeSource(
		    """
		    secret    = "12345678901234567890123456789012";
		    original  = jwtCreate( { sub: "u2" }, secret, "HS256" );
		    p1        = jwtVerify( original, secret, "HS256" );
		    newToken  = jwtRefresh( original, secret, "HS256" );
		    p2        = jwtVerify( newToken, secret, "HS256" );
		    result    = ( p1.jti != p2.jti );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "jwtRefresh with expireIn sets new exp claim" )
	@Test
	public void testRefreshWithExpireIn() {
		runtime.executeSource(
		    """
		    secret   = "12345678901234567890123456789012";
		    original = jwtCreate( { sub: "u3" }, secret, "HS256" );
		    newToken = jwtRefresh( original, secret, "HS256", { expireIn: 3600 } );
		    payload  = jwtVerify( newToken, secret, "HS256" );
		    result   = structKeyExists( payload, "exp" );
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

	@DisplayName( "jwtRefresh allowExpired allows refreshing an expired token" )
	@Test
	public void testRefreshAllowExpired() {
		runtime.executeSource(
		    """
		    secret   = "12345678901234567890123456789012";
		    expired  = jwtCreate( { sub: "u4", exp: dateAdd( "s", -300, now() ) }, secret, "HS256" );
		    newToken = jwtRefresh( expired, secret, "HS256", { allowExpired: true, expireIn: 3600 } );
		    payload  = jwtVerify( newToken, secret, "HS256" );
		    result   = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "u4" );
	}

	@DisplayName( "jwtRefresh throws when token is expired and allowExpired is false" )
	@Test
	public void testRefreshThrowsForExpiredWithoutFlag() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    expired = jwtCreate( { sub: "u5", exp: dateAdd( "s", -300, now() ) }, secret, "HS256" );
		    jwtRefresh( expired, secret, "HS256", { clockSkew: 0 } );
		    """,
		    context
		) );
	}

	@DisplayName( "jwtRefresh throws for a tampered token" )
	@Test
	public void testRefreshThrowsForTamperedToken() {
		assertThrows( BoxRuntimeException.class, () -> runtime.executeSource(
		    """
		    secret   = "12345678901234567890123456789012";
		    token    = jwtCreate( { sub: "u6" }, secret, "HS256" );
		    tampered = left( token, len( token ) - 1 ) & ( right( token, 1 ) == "A" ? "B" : "A" );
		    jwtRefresh( tampered, secret, "HS256" );
		    """,
		    context
		) );
	}

}
