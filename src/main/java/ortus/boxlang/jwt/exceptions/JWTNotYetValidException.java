/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown when a JWT's {@code nbf} claim is in the future. Subclass of
 * {@code JWTVerificationException}. Caught as {@code bxjwt.JWTNotYetValidException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTNotYetValidException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTNotYetValidException";

	public JWTNotYetValidException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTNotYetValidException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
