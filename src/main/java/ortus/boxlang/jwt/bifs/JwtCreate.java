/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that creates a signed JWT (JWS) using HMAC, RSA, or EC keys.
 * Delegates to {@code JWTService.create()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Creates a signed JWT (JWS) using HMAC, RSA, or EC keys. Delegates to JWTService.create()." )
public class JwtCreate extends BaseJwtBif {

	/**
	 * Constructor for JwtCreate BIF. Declares the arguments for the BIF.
	 */
	public JwtCreate() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRUCT, KeyDictionary.payload ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRING, KeyDictionary.algorithm ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Creates a signed JWT (JWS) from the supplied payload.
	 *
	 * The key can be provided as:
	 * <ul>
	 * <li>a named key from the module key registry</li>
	 * <li>a raw secret (for HMAC algorithms)</li>
	 * <li>a PEM/JWK-compatible value that {@code JWTService.parseKey()} can parse</li>
	 * </ul>
	 *
	 * The algorithm is resolved in this order:
	 * <ol>
	 * <li>explicit {@code algorithm} argument</li>
	 * <li>named key algorithm (when {@code key} is a registered key name)</li>
	 * <li>module setting {@code defaultAlgorithm} (fallback {@code HS256})</li>
	 * </ol>
	 *
	 * Returns the serialized compact JWT string.
	 *
	 * <pre>{@code
	 * secret = "12345678901234567890123456789012";
	 * token  = jwtCreate( { sub: "user-123", iss: "my-api" }, secret, "HS256" );
	 * }</pre>
	 *
	 * <pre>{@code
	 * // Uses a key registered in ModuleConfig settings.keys
	 * token = jwtCreate( { sub: "user-123" }, "myapp-signing" );
	 * }</pre>
	 *
	 * <pre>{@code
	 * token = jwtCreate(
	 *     { sub: "user-123", aud: "api" },
	 *     secret,
	 *     "HS256",
	 *     { headers: { kid: "v1", typ: "JWT" } }
	 * );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.payload Claims payload to encode in the JWT. Must be a struct.
	 *
	 * @argument.key Signing key material. Can be a key name, key object, PEM/JWK value, or HMAC secret.
	 *               Optional when {@code defaultSigningKey} is configured.
	 *
	 * @argument.algorithm Signing algorithm (for example, {@code HS256}, {@code RS256}, {@code ES256}).
	 *                     Optional when resolved from key metadata or module defaults.
	 *
	 * @argument.options Optional signing options, including custom JOSE headers.
	 *
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service		= getJWTService( context );
		IStruct				payload		= StructCaster.cast( arguments.get( KeyDictionary.payload ) );

		// Key resolution and algorithm resolution are handled in the resolveKey method, which considers the key argument, defaults, and key metadata.
		java.security.Key	key			= resolveSigningKey( service, arguments );
		String				algorithm	= resolveAlgorithm( service, arguments );

		// Options are passed directly to the service method for flexibility, as they may include custom headers or other signing options.
		IStruct				options		= getOptions( arguments );

		// Delegate to the JWTService to create and sign the JWT, returning the compact serialized string.
		return service.create( payload, key, algorithm, options );
	}

}
