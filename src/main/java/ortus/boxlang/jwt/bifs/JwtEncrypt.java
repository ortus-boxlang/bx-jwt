/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that encrypts a payload as a JWE token using RSA, EC, or
 * direct symmetric key management. Delegates to {@code JWTService.encrypt()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Encrypts a payload as a JWE token using RSA, EC, or direct symmetric key management. Delegates to JWTService.encrypt()." )
public class JwtEncrypt extends BaseJwtBif {

	/**
	 * Constructor for JwtEncrypt BIF. Declares the arguments for the BIF.
	 */
	public JwtEncrypt() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.ANY, KeyDictionary.payload ),
		    new Argument( false, Argument.ANY, KeyDictionary.key ),
		    new Argument( false, Argument.STRUCT, KeyDictionary.options, new Struct() )
		};
	}

	/**
	 * Encrypts a payload as a JWE token using the provided key and options.
	 *
	 * Supports structured payloads (claims) and string payloads (for nested JWT workflows).
	 *
	 * Returns the serialized compact JWE string.
	 *
	 * <pre>{@code
	 * secret = "12345678901234567890123456789012";
	 * token = jwtEncrypt(
	 *     { sub: "enc-user", pii: "sensitive" },
	 *     secret,
	 *     { keyAlgorithm: "dir", encAlgorithm: "A256GCM" }
	 * );
	 * }</pre>
	 *
	 * <pre>{@code
	 * token = jwtEncrypt(
	 *     { sub: "enc-user" },
	 *     "partner-public",
	 *     { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" }
	 * );
	 * }</pre>
	 *
	 * <pre>{@code
	 * // Nested JWT: encrypt a pre-signed JWS string
	 * nested = jwtEncrypt( signedToken, publicKey, { keyAlgorithm: "RSA-OAEP-256", encAlgorithm: "A256GCM" } );
	 * }</pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.payload Payload to encrypt. Can be a struct or a string.
	 *
	 * @argument.key Encryption key material. Can be a key name, key object, PEM/JWK value, or symmetric secret.
	 *               Optional when {@code defaultEncryptionKey} is configured.
	 *
	 * @argument.options Encryption options such as {@code keyAlgorithm}, {@code encAlgorithm}, and custom headers.
	 *
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service	= getJWTService( context );
		Object				payload	= arguments.get( KeyDictionary.payload );
		java.security.Key	key		= resolveEncryptionKey( service, arguments );
		IStruct				options	= getOptions( arguments );
		return service.encrypt( payload, key, options );
	}

}
