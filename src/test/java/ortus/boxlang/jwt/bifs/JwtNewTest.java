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

public class JwtNewTest extends BaseIntegrationTest {

	@DisplayName( "jwtNew builder creates signed JWT" )
	@Test
	public void testJwtNewBuilderSign() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtNew()
		        .subject( "builderUser" )
		        .issuer( "builderApp" )
		        .claim( "roles", [ "admin" ] )
		        .header( "kid", "v1" )
		        .sign( secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "builderUser" );
	}

	@DisplayName( "jwtNew builder creates encrypted JWT" )
	@Test
	public void testJwtNewBuilderEncrypt() {
		runtime.executeSource(
		    """
		    secret = "12345678901234567890123456789012";
		    token = jwtNew()
		        .subject( "builderEncUser" )
		        .claim( "ssn", "123-45-6789" )
		        .encrypt( secret, "dir", "A256GCM" );
		    payload = jwtDecrypt( token, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "builderEncUser" );
	}

	@DisplayName( "jwtNew returns an initialized builder" )
	@Test
	public void testJwtNewReturnsBuilder() {
		runtime.executeSource(
		    """
		    builder = jwtNew();
		    token = builder.subject( "builderObject" ).sign( "12345678901234567890123456789012", "HS256" );
		    payload = jwtVerify( token, "12345678901234567890123456789012", "HS256" );
		    result = payload.sub;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "builderObject" );
	}

	@DisplayName( "jwtNew withPayload sets entire struct payload" )
	@Test
	public void testJwtNewWithPayload() {
		runtime.executeSource(
		    """
		    secret  = "12345678901234567890123456789012";
		    token   = jwtNew()
		        .withPayload( { sub: "payloadUser", iss: "myapp", role: "admin" } )
		        .sign( secret, "HS256" );
		    payload = jwtVerify( token, secret, "HS256" );
		    result  = payload.sub & ":" & payload.role;
		    """,
		    context
		);
		assertThat( ( String ) variables.get( "result" ) ).isEqualTo( "payloadUser:admin" );
	}

}
