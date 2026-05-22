/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that decrypts a JWE token and returns the payload claims.
 * Delegates to {@code JWTService.decrypt()}.
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

@BoxBIF( description = "Decrypts a JWE token and returns the payload claims. Delegates to JWTService.decrypt()." )
public class JwtDecrypt extends BaseJwtBif {

	/**
	 * Constructor for JwtDecrypt BIF. Declares the arguments for the BIF.
	 */
	public JwtDecrypt() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, KeyDictionary.token ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Decrypts a compact JWE token and returns the decrypted payload.
	 *
	 * For structured payloads, this returns a claims struct. For nested JWT scenarios,
	 * the returned struct includes the nested payload string for follow-up verification.
	 *
	 * <pre>{@code
	 * payload = jwtDecrypt(
	 *     token,
	 *     "12345678901234567890123456789012",
	 *     { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
	 * );
	 * writeDump( payload.sub );
	 * }</pre>
	 *
	 * <pre>{@code
	 * payload = jwtDecrypt(
	 *     token,
	 *     "myapp-private",
	 *     { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" }
	 * );
	 * }</pre>
	 *
	 * <pre>{@code
	 * decrypted = jwtDecrypt( nestedToken, outerPrivateKey, { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" } );
	 * innerPayload = jwtVerify( decrypted.payload, innerPublicKey, "RS256" );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The JWE token to decrypt.
	 *
	 * @argument.key Decryption key material. Can be a key name, key object, PEM/JWK value, or symmetric secret.
	 *               Optional when {@code defaultDecryptionKey} is configured.
	 *
	 * @argument.options Decryption options such as {@code keyAlgorithm} and {@code encAlgorithm}.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service	= getJWTService( context );
		String				token	= StringCaster.cast( arguments.get( TOKEN_ARGUMENT ) );
		java.security.Key	key		= resolveDecryptionKey( service, arguments );
		IStruct				options	= getOptions( arguments );
		return service.decrypt( token, key, options );
	}

}
