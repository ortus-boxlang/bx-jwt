/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown when JWT signature verification fails, the tampered token is invalid,
 * or a claim assertion fails. Caught as {@code bxjwt.JWTVerificationException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTVerificationException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTVerificationException";

	public JWTVerificationException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTVerificationException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
