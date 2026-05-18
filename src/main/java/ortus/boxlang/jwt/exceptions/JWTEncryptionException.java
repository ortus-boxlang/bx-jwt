/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown when JWE encryption or decryption fails. Caught as
 * {@code bxjwt.JWTEncryptionException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTEncryptionException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTEncryptionException";

	public JWTEncryptionException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTEncryptionException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
