/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that verifies a signed JWT (JWS) signature and validates
 * claims (iss, aud, exp, nbf, etc.). Delegates to {@code JWTService.verify()}.
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

@BoxBIF( description = "Verifies a signed JWT (JWS) signature and validates claims (iss, aud, exp, nbf, etc.). Delegates to JWTService.verify()." )
public class JwtVerify extends BaseJwtBif {

	/**
	 * Constructor for JwtVerify BIF. Declares the arguments for the BIF.
	 */
	public JwtVerify() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, KeyDictionary.token ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRING, KeyDictionary.algorithm ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Verifies a signed JWT (JWS) signature and validates standard/custom claims.
	 *
	 * Key resolution attempts:
	 * <ol>
	 * <li>explicit {@code key} argument</li>
	 * <li>module {@code defaultVerifyKey}</li>
	 * <li>module {@code defaultSigningKey} (for symmetric/shared key setups)</li>
	 * </ol>
	 *
	 * Returns the verified claims as a struct.
	 *
	 * <pre>{@code
	 * payload = jwtVerify( token, "12345678901234567890123456789012", "HS256" );
	 * writeDump( payload.sub );
	 * }</pre>
	 *
	 * <pre>{@code
	 * // Uses key and algorithm from key registry defaults
	 * payload = jwtVerify( token, "myapp-signing" );
	 * }</pre>
	 *
	 * <pre>{@code
	 * payload = jwtVerify(
	 *     token,
	 *     secret,
	 *     "HS256",
	 *     { claims: { iss: "my-api", aud: "mobile-client" } }
	 * );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The JWT token to verify.
	 *
	 * @argument.key Verification key material. Can be a key name, key object, PEM/JWK value, or HMAC secret.
	 *               Optional when defaults are configured.
	 *
	 * @argument.algorithm Verification algorithm (for example, {@code HS256}, {@code RS256}, {@code ES256}).
	 *                     Optional when resolved from key metadata or module defaults.
	 *
	 * @argument.options Optional validation options such as claim matching, clock skew, and expected issuer/audience.
	 *
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service		= getJWTService( context );
		String				token		= StringCaster.cast( arguments.get( TOKEN_ARGUMENT ) );
		java.security.Key	key			= resolveVerificationKey( service, arguments );
		String				algorithm	= resolveAlgorithm( service, arguments );
		IStruct				options		= getOptions( arguments );
		return service.verify( token, key, algorithm, options );
	}

}
