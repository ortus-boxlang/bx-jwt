/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that generates a cryptographically random HMAC secret.
 * Delegates to {@code JWTService.generateSecret()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.IntegerCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;

@BoxBIF( description = "Generates a cryptographically random Base64-encoded HMAC secret of the requested bit length (default 256)." )
public class JwtGenerateSecret extends BaseJwtBif {

	public JwtGenerateSecret() {
		declaredArguments = new Argument[] {
		    new Argument( false, Argument.INTEGER, KeyDictionary.bits, 256 )
		};
	}

	/**
	 * Generates a random HMAC secret suitable for use with HS256, HS384, or HS512.
	 *
	 * <ul>
	 * <li>HS256 → 256 bits (default)</li>
	 * <li>HS384 → 384 bits</li>
	 * <li>HS512 → 512 bits</li>
	 * </ul>
	 *
	 * <pre>{@code
	 * secret = jwtGenerateSecret();           // 256-bit (HS256)
	 * secret = jwtGenerateSecret( 512 );      // 512-bit (HS512)
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.bits Key length in bits. Must be >= 128 and a multiple of 8.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService	service	= getJWTService( context );
		int			bits	= IntegerCaster.cast( arguments.getOrDefault( KeyDictionary.bits, 256 ) );
		return service.generateSecret( bits );
	}

}
