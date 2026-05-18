/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown when a JWT's {@code exp} claim is in the past. Subclass of
 * {@code JWTVerificationException}. Caught as {@code bxjwt.JWTExpiredException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTExpiredException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTExpiredException";

	public JWTExpiredException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTExpiredException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
