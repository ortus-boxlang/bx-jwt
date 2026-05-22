/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.exceptions.JWTKeyException;
import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.IStruct;

/**
 * Shared base class for JWT BIFs containing common service, key, algorithm,
 * options, and module-settings resolution helpers.
 */
public abstract class BaseJwtBif extends BIF {

	protected static final Key	KEY_ARGUMENT	= KeyDictionary.key;
	protected static final Key	TOKEN_ARGUMENT	= KeyDictionary.token;

	/**
	 * Retrieves the module JWT service from the runtime global service registry.
	 *
	 * @param context The active BoxLang execution context.
	 *
	 * @return The initialized JWTService instance.
	 */
	protected JWTService getJWTService( IBoxContext context ) {
		return ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );
	}

	/**
	 * Returns the optional options struct from BIF arguments.
	 *
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return The options struct when present, otherwise null.
	 */
	protected IStruct getOptions( ArgumentsScope arguments ) {
		Object opts = arguments.get( KeyDictionary.options );
		if ( opts instanceof IStruct s ) {
			return s;
		}
		return null;
	}

	/**
	 * Resolves a module setting string value with a fallback default.
	 *
	 * @param service      The JWT service used to access runtime module settings.
	 * @param settingKey   The module setting key to resolve.
	 * @param defaultValue The fallback value to return when the setting does not exist.
	 *
	 * @return The resolved setting value or the provided default.
	 */
	protected String getDefaultSetting( JWTService service, Key settingKey, String defaultValue ) {
		if ( !service.getRuntime().getModuleService().hasModule( KeyDictionary.moduleName ) ) {
			return defaultValue;
		}
		IStruct settings = service.getRuntime().getModuleService().getModuleSettings( KeyDictionary.moduleName );
		if ( settings == null || !settings.containsKey( settingKey ) ) {
			return defaultValue;
		}
		return StringCaster.cast( settings.get( settingKey ) );
	}

	/**
	 * Resolves the JWT algorithm from arguments, key metadata, or module defaults.
	 *
	 * Resolution order:
	 * <ol>
	 * <li>explicit {@code algorithm} argument</li>
	 * <li>registered key algorithm when the key argument is a named key</li>
	 * <li>module setting {@code defaultAlgorithm} with fallback {@code HS256}</li>
	 * </ol>
	 *
	 * @param service   The JWT service used for key metadata lookups.
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return The resolved algorithm string.
	 */
	protected String resolveAlgorithm( JWTService service, ArgumentsScope arguments ) {
		Object algArg = arguments.get( KeyDictionary.algorithm );
		if ( algArg != null && !"".equals( algArg ) ) {
			return StringCaster.cast( algArg );
		}
		Object keyArg = arguments.get( KEY_ARGUMENT );
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.getKey( keyStr ).getAlgorithm();
		}
		return getDefaultSetting( service, KeyDictionary.defaultAlgorithm, "HS256" );
	}

	/**
	 * Resolves signing key material from arguments or module defaults.
	 *
	 * @param service   The JWT service used to resolve and parse keys.
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return A signing-capable key instance.
	 *
	 * @throws JWTKeyException when no key is provided and no signing default exists.
	 */
	protected java.security.Key resolveSigningKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( KEY_ARGUMENT );
		if ( hasNoValue( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultSigningKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveSigningKey( defaultKey );
			}
			throw new JWTKeyException( "No key provided and no defaultSigningKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveSigningKey( keyStr );
		}
		return service.parseKey( keyArg, resolveAlgorithm( service, arguments ) );
	}

	/**
	 * Resolves verification key material from arguments or module defaults.
	 *
	 * @param service   The JWT service used to resolve and parse keys.
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return A verification-capable key instance.
	 *
	 * @throws JWTKeyException when no key is provided and no verification default exists.
	 */
	protected java.security.Key resolveVerificationKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( KEY_ARGUMENT );
		if ( hasNoValue( keyArg ) ) {
			String verifyKey = getDefaultSetting( service, KeyDictionary.defaultVerifyKey, "" );
			if ( !verifyKey.isEmpty() ) {
				return service.resolveVerificationKey( verifyKey );
			}
			String signKey = getDefaultSetting( service, KeyDictionary.defaultSigningKey, "" );
			if ( !signKey.isEmpty() && service.hasKey( signKey ) ) {
				return service.resolveVerificationKey( signKey );
			}
			throw new JWTKeyException( "No key provided and no default verification key configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveVerificationKey( keyStr );
		}
		return service.parseKey( keyArg, resolveAlgorithm( service, arguments ) );
	}

	/**
	 * Resolves encryption key material from arguments or module defaults.
	 *
	 * @param service   The JWT service used to resolve and parse keys.
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return An encryption-capable key instance.
	 *
	 * @throws JWTKeyException when no key is provided and no encryption default exists.
	 */
	protected java.security.Key resolveEncryptionKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( KEY_ARGUMENT );
		if ( hasNoValue( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultEncryptionKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveEncryptionKey( defaultKey );
			}
			throw new JWTKeyException( "No key provided and no defaultEncryptionKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveEncryptionKey( keyStr );
		}
		return service.parseKey( keyArg, "RSA-OAEP-256" );
	}

	/**
	 * Resolves decryption key material from arguments or module defaults.
	 *
	 * @param service   The JWT service used to resolve and parse keys.
	 * @param arguments The inbound BIF argument scope.
	 *
	 * @return A decryption-capable key instance.
	 *
	 * @throws JWTKeyException when no key is provided and no decryption default exists.
	 */
	protected java.security.Key resolveDecryptionKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( KEY_ARGUMENT );
		if ( hasNoValue( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultDecryptionKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveDecryptionKey( defaultKey );
			}
			throw new JWTKeyException( "No key provided and no defaultDecryptionKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveDecryptionKey( keyStr );
		}
		return service.parseKey( keyArg, "RSA-OAEP-256" );
	}

	/**
	 * Determines whether a key argument should be considered absent.
	 *
	 * @param value The value to inspect.
	 *
	 * @return True when null or an empty string; false otherwise.
	 */
	private boolean hasNoValue( Object value ) {
		return value == null || "".equals( value );
	}
}