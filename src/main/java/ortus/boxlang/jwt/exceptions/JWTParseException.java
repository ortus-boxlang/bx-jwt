/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Thrown when a JWT or JWE token string is malformed or cannot be parsed.
 * Caught as {@code bxjwt.JWTParseException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTParseException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTParseException";

	public JWTParseException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTParseException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
