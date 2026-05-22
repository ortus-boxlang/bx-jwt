/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that generates an asymmetric RSA or EC key pair for JWT signing.
 * Delegates to {@code JWTService.generateKeyPair()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;

@BoxBIF( description = "Generates an asymmetric RSA or EC key pair and returns PEM-encoded privateKey and publicKey strings." )
public class JwtGenerateKeyPair extends BaseJwtBif {

	public JwtGenerateKeyPair() {
		declaredArguments = new Argument[] {
		    new Argument( false, Argument.STRING, KeyDictionary.algorithm, "RS256" )
		};
	}

	/**
	 * Generates a new asymmetric key pair for the given algorithm and returns both keys as PEM strings.
	 *
	 * <ul>
	 * <li>RS256 / RS384 → 2048-bit RSA</li>
	 * <li>RS512 → 4096-bit RSA</li>
	 * <li>ES256 → P-256, ES384 → P-384, ES512 → P-521</li>
	 * </ul>
	 *
	 * <pre>{@code
	 * keys = jwtGenerateKeyPair( "RS256" );
	 * token = jwtCreate( payload, keys.privateKey, "RS256" );
	 * jwtVerify( token, keys.publicKey, "RS256" );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.algorithm The JWS algorithm to generate keys for (RS256, RS384, RS512, ES256, ES384, ES512).
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService	service		= getJWTService( context );
		String		algorithm	= StringCaster.cast( arguments.getOrDefault( KeyDictionary.algorithm, "RS256" ) );
		return service.generateKeyPair( algorithm );
	}

}
