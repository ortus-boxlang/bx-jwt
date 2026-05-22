/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that decodes a signed JWT (JWS) without verifying the signature.
 * Useful for inspecting the header (kid, alg) before choosing which key to verify with.
 * Delegates to {@code JWTService.decode()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;

@BoxBIF( description = "Decodes a signed JWT without verifying the signature. Returns a struct with 'header' and 'payload' keys." )
public class JwtDecode extends BaseJwtBif {

	public JwtDecode() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, KeyDictionary.token )
		};
	}

	/**
	 * Decodes a JWT token without verifying the signature. Returns header and payload as structs.
	 *
	 * <pre>{@code
	 * decoded = jwtDecode( token );
	 * kid     = decoded.header.kid;
	 * sub     = decoded.payload.sub;
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The compact JWT string to decode.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService	service	= getJWTService( context );
		String		token	= StringCaster.cast( arguments.get( TOKEN_ARGUMENT ) );
		return service.decode( token );
	}

}
