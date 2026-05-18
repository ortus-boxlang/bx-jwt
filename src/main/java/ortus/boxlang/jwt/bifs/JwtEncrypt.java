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
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Encrypts a payload as a JWE token using RSA, EC, or direct symmetric key management. Delegates to JWTService.encrypt()." )
public class JwtEncrypt extends BIF {

	/**
	 * Constructor for JwtEncrypt BIF. Declares the arguments for the BIF.
	 */
	public JwtEncrypt() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.ANY, Key.of( "payload" ) ),
		    new Argument( false, Argument.ANY, Key.of( "key" ) ),
		    new Argument( false, Argument.STRUCT, Key.of( "options" ), new Struct() )
		};
	}

	/**
	 * Encrypts a payload as a JWE token using the provided key and options.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.payload The payload to encrypt as a JWE token.
	 *
	 * @argument.key The key to use for encryption. Can be a string (key name) or a key object. Optional if a default is configured.
	 *
	 * @argument.options Additional options for encryption. Optional.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service	= ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );
		Object				payload	= arguments.get( Key.of( "payload" ) );
		java.security.Key	key		= resolveKey( service, arguments );
		IStruct				options	= getOptions( arguments );
		return service.encrypt( payload, key, options );
	}

	/**
	 * Resolves the encryption key from the arguments or module settings.
	 *
	 * @param service   The JWTService instance.
	 * @param arguments The arguments scope containing the key.
	 *
	 * @return The resolved encryption key.
	 *
	 * @throws ortus.boxlang.jwt.exceptions.JWTKeyException if no key is provided or configured.
	 */
	private java.security.Key resolveKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( Key.of( "key" ) );
		if ( keyArg == null || "".equals( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultEncryptionKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveEncryptionKey( defaultKey );
			}
			throw new ortus.boxlang.jwt.exceptions.JWTKeyException(
			    "No key provided and no defaultEncryptionKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveEncryptionKey( keyStr );
		}
		return service.parseKey( keyArg, "RSA-OAEP-256" );
	}

	/**
	 * Retrieves the options struct from the arguments, if present.
	 *
	 * @param arguments The arguments scope.
	 *
	 * @return The options struct, or null if not provided.
	 */
	private IStruct getOptions( ArgumentsScope arguments ) {
		Object opts = arguments.get( Key.of( "options" ) );
		if ( opts instanceof IStruct s ) {
			return s;
		}
		return null;
	}

	/**
	 * Retrieves a default setting from the module settings or returns the provided default value.
	 *
	 * @param service      The JWTService instance.
	 * @param settingKey   The key for the setting to retrieve.
	 * @param defaultValue The value to return if the setting is not found.
	 *
	 * @return The setting value as a string, or the default value if not found.
	 */
	public String getDefaultSetting( JWTService service, Key settingKey, String defaultValue ) {
		if ( !service.getRuntime().getModuleService().hasModule( KeyDictionary.moduleName ) ) {
			return defaultValue;
		}
		IStruct settings = service.getRuntime().getModuleService().getModuleSettings( KeyDictionary.moduleName );
		if ( settings == null || !settings.containsKey( settingKey ) ) {
			return defaultValue;
		}
		return StringCaster.cast( settings.get( settingKey ) );
	}

}
