/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that creates a signed JWT (JWS) using HMAC, RSA, or EC keys.
 * Delegates to {@code JWTService.create()}.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Creates a signed JWT (JWS) using HMAC, RSA, or EC keys. Delegates to JWTService.create()." )
public class JwtCreate extends BIF {

	/**
	 * Constructor for JwtCreate BIF. Declares the arguments for the BIF.
	 */
	public JwtCreate() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRUCT, Key.of( "payload" ) ),
		    new Argument( false, Argument.ANY, Key.of( "key" ) ),
		    new Argument( false, Argument.STRING, Key.of( "algorithm" ) ),
		    new Argument( false, Argument.STRUCT, Key.of( "options" ), new Struct() )
		};
	}

	/**
	 * Creates a signed JWT (JWS) using the provided payload, key, algorithm, and options.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.payload The payload to encode in the JWT. Must be a struct.
	 *
	 * @argument.key The key to use for signing. Can be a string (key name) or a key object. Optional if a default is configured.
	 *
	 * @argument.algorithm The signing algorithm to use (e.g., HS256, RS256). Optional; defaults to module setting or HS256.
	 *
	 * @argument.options Additional options for JWT creation (expiration, issuer, etc.). Optional.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service		= ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );
		IStruct				payload		= StructCaster.cast( arguments.get( Key.of( "payload" ) ) );
		java.security.Key	key			= resolveKey( service, arguments, "signing" );
		String				algorithm	= resolveAlgorithm( service, arguments, "signing" );
		IStruct				options		= getOptions( arguments );
		return service.create( payload, key, algorithm, options );
	}

	/**
	 * Resolves the signing key from the arguments or module settings.
	 *
	 * @param service   The JWTService instance.
	 * @param arguments The arguments scope containing the key.
	 * @param operation The operation type (e.g., "signing").
	 *
	 * @return The resolved signing key.
	 *
	 * @throws ortus.boxlang.jwt.exceptions.JWTKeyException if no key is provided or configured.
	 */
	private java.security.Key resolveKey( JWTService service, ArgumentsScope arguments, String operation ) {
		Object keyArg = arguments.get( Key.of( "key" ) );
		if ( keyArg == null || "".equals( keyArg ) ) {
			String defaultKey = getDefaultSetting( service, KeyDictionary.defaultSigningKey, "" );
			if ( !defaultKey.isEmpty() ) {
				return service.resolveSigningKey( defaultKey );
			}
			throw new ortus.boxlang.jwt.exceptions.JWTKeyException(
			    "No key provided and no defaultSigningKey configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveSigningKey( keyStr );
		}
		String algorithm = resolveAlgorithm( service, arguments, operation );
		return service.parseKey( keyArg, algorithm );
	}

	/**
	 * Resolves the algorithm to use for signing from the arguments or module settings.
	 *
	 * @param service   The JWTService instance.
	 * @param arguments The arguments scope containing the algorithm.
	 * @param operation The operation type (e.g., "signing").
	 *
	 * @return The algorithm as a string.
	 */
	private String resolveAlgorithm( JWTService service, ArgumentsScope arguments, String operation ) {
		Object algArg = arguments.get( Key.of( "algorithm" ) );
		if ( algArg != null && !"".equals( algArg ) ) {
			return StringCaster.cast( algArg );
		}
		Object keyArg = arguments.get( Key.of( "key" ) );
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.getKey( keyStr ).getAlgorithm();
		}
		return getDefaultSetting( service, KeyDictionary.defaultAlgorithm, "HS256" );
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
