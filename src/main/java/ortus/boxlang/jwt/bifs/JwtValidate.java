/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that verifies a signed JWT and returns a boolean result instead of
 * throwing an exception. Delegates to {@code JWTService.verify()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Verifies a signed JWT and returns true if valid, false otherwise. Does not throw exceptions." )
public class JwtValidate extends BaseJwtBif {

	public JwtValidate() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, KeyDictionary.token ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRING, KeyDictionary.algorithm ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Validates a JWT token, returning {@code true} when the signature is valid and all
	 * claims pass, {@code false} for any failure (bad signature, expired, wrong claims, etc.).
	 *
	 * <pre>{@code
	 * if ( jwtValidate( token, secret, "HS256" ) ) {
	 *     payload = jwtVerify( token, secret, "HS256" );
	 * }
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The JWT token to validate.
	 * 
	 * @argument.key Verification key material. Optional when defaults are configured.
	 * 
	 * @argument.algorithm Verification algorithm. Optional when resolved from key metadata or defaults.
	 * 
	 * @argument.options Optional validation options (claim matching, clockSkew, etc.).
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService service = getJWTService( context );
		try {
			String				token		= StringCaster.cast( arguments.get( TOKEN_ARGUMENT ) );
			java.security.Key	key			= resolveVerificationKey( service, arguments );
			String				algorithm	= resolveAlgorithm( service, arguments );
			service.verify( token, key, algorithm, getOptions( arguments ) );
			return true;
		} catch ( Exception e ) {
			return false;
		}
	}

}
