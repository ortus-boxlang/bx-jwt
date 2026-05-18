/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown on key configuration errors: unknown key, missing side for an
 * operation, PEM parse failure, or invalid JWK. Caught as {@code bxjwt.JWTKeyException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTKeyException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTKeyException";

	public JWTKeyException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTKeyException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
