/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that decrypts a JWE token and returns the payload claims.
 * Delegates to {@code JWTService.decrypt()}.
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

@BoxBIF( description = "Decrypts a JWE token and returns the payload claims. Delegates to JWTService.decrypt()." )
public class JwtDecrypt extends BIF {

	/**
	 * Constructor for JwtDecrypt BIF. Declares the arguments for the BIF.
	 */
	public JwtDecrypt() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, Key.of( "token" ) ),
		    new Argument( false, Argument.ANY, Key.of( "key" ) ),
		    new Argument( false, Argument.STRUCT, Key.of( "options" ), new Struct() )
		};
	}

	/**
	 * Decrypts a JWE token and returns the payload claims.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The JWE token to decrypt.
	 *
	 * @argument.key The key to use for decryption. Can be a string (key name) or a key object. Optional if a default is configured.
	 *
	 * @argument.options Additional options for decryption. Optional.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service	= ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );
		String				token	= StringCaster.cast( arguments.get( Key.of( "token" ) ) );
		java.security.Key	key		= resolveKey( service, arguments );
		IStruct				options	= getOptions( arguments );
		return service.decrypt( token, key, options );
	}

	/**
	 * Resolves the decryption key from the arguments or module settings.
	 *
	 * @param service   The JWTService instance.
	 * @param arguments The arguments scope containing the key.
	 *
	 * @return The resolved decryption key.
	 *
	 * @throws ortus.boxlang.jwt.exceptions.JWTKeyException if no key is provided or configured.
	 */
	private java.security.Key resolveKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( Key.of( "key" ) );
		if ( keyArg == null || "".equals( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultDecryptionKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveDecryptionKey( defaultKey );
			}
			throw new ortus.boxlang.jwt.exceptions.JWTKeyException(
			    "No key provided and no defaultDecryptionKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveDecryptionKey( keyStr );
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
