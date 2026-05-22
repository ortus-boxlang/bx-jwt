/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that creates and returns a {@code JwtBuilder} BoxLang class
 * instance pre-seeded with the {@code JWTService} for fluent JWT construction.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.runnables.IClassRunnable;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;

@BoxBIF( description = "Creates and returns a JwtBuilder BoxLang class instance pre-seeded with the JWTService for fluent JWT construction." )
public class JwtNew extends BaseJwtBif {

	private static final String className = "bxModules.bxjwt.models.JwtBuilder";

	/**
	 * Creates and returns a fluent {@code JwtBuilder} instance.
	 *
	 * The builder is initialized with the module {@code JWTService}, allowing chainable
	 * claim/header composition and final token generation via {@code sign()} or {@code encrypt()}.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF. (No arguments required for this BIF.)
	 *
	 *                  <pre>{@code
	 * token = jwtNew()
	 *     .subject( "user-123" )
	 *     .issuer( "my-api" )
	 *     .claim( "roles", [ "admin" ] )
	 *     .sign( "12345678901234567890123456789012", "HS256" );
	 * }</pre>
	 *
	 *                  <pre>{@code
	 * token = jwtNew()
	 *     .subject( "user-123" )
	 *     .header( "kid", "rsa-key-1" )
	 *     .encrypt( publicKey, "RSA-OAEP-256", "A256GCM" );
	 * }</pre>
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService		service	= getJWTService( context );

		// Create the Builder class
		IClassRunnable	builder	= ( IClassRunnable ) BoxRuntime.getInstance()
		    .getFunctionService()
		    .getGlobalFunction( Key.createObject )
		    .invoke( context, new Object[] { className }, false, Key.createObject );

		return builder.dereferenceAndInvoke( context, Key.init, new Object[] { service }, false );
	}

}
