/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that verifies an existing JWT and re-issues it with fresh time claims.
 * Delegates to {@code JWTService.refresh()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Verifies an existing JWT and re-issues it with fresh iat/jti/exp claims. Supports allowExpired and expireIn options." )
public class JwtRefresh extends BaseJwtBif {

	public JwtRefresh() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, KeyDictionary.token ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRING, KeyDictionary.algorithm ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Verifies an existing JWT and re-issues it with refreshed time claims ({@code iat}, {@code jti},
	 * optionally {@code exp}). All non-time claims are preserved.
	 *
	 * <p>
	 * Options:
	 * </p>
	 * <ul>
	 * <li>{@code allowExpired} (boolean) — allow refreshing a token that has already expired (signature is still verified)</li>
	 * <li>{@code expireIn} (numeric) — seconds until the refreshed token expires</li>
	 * <li>{@code headers} (struct) — custom JOSE headers to include in the new token</li>
	 * </ul>
	 *
	 * <pre>{@code
	 * newToken = jwtRefresh( oldToken, secret, "HS256" );
	 * newToken = jwtRefresh( oldToken, secret, "HS256", { expireIn: 3600, allowExpired: true } );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The existing JWT to refresh.
	 * 
	 * @argument.key Key material used for both verification and re-signing. Optional when defaults are configured.
	 * 
	 * @argument.algorithm The JWS algorithm. Optional when resolved from key metadata or defaults.
	 * 
	 * @argument.options Optional refresh options: allowExpired, expireIn, headers.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service		= getJWTService( context );
		String				token		= StringCaster.cast( arguments.get( TOKEN_ARGUMENT ) );
		java.security.Key	signingKey	= resolveSigningKey( service, arguments );
		java.security.Key	verifyKey	= resolveVerificationKey( service, arguments );
		String				algorithm	= resolveAlgorithm( service, arguments );
		IStruct				options		= getOptions( arguments );
		return service.refresh( token, signingKey, verifyKey, algorithm, options );
	}

}
