/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */
/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * Base catch-all exception for all JWT module errors. Caught in BoxLang
 * as type {@code bxjwt.JWTException}.
 */
package ortus.boxlang.jwt.exceptions;

import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class JWTException extends BoxRuntimeException {

	private static final String TYPE = "bxjwt.JWTException";

	public JWTException( String message ) {
		super( message, null, TYPE, null, null );
	}

	public JWTException( String message, Throwable cause ) {
		super( message, null, TYPE, null, cause );
	}
}
