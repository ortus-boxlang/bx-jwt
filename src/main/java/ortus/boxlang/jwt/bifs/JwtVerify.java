/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that verifies a signed JWT (JWS) signature and validates
 * claims (iss, aud, exp, nbf, etc.). Delegates to {@code JWTService.verify()}.
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

@BoxBIF( description = "Verifies a signed JWT (JWS) signature and validates claims (iss, aud, exp, nbf, etc.). Delegates to JWTService.verify()." )
public class JwtVerify extends BIF {

	public JwtVerify() {
		declaredArguments = new Argument[] {
		    new Argument( true, Argument.STRING, Key.of( "token" ) ),
		    new Argument( false, Argument.ANY, Key.of( "key" ) ),
		    new Argument( false, Argument.STRING, Key.of( "algorithm" ) ),
		    new Argument( false, Argument.STRUCT, Key.of( "options" ), new Struct() )
		};
	}

	/**
	 * Verifies a signed JWT (JWS) signature and validates claims (iss, aud, exp, nbf, etc.).
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.token The JWT token to verify.
	 *
	 * @argument.key The key to use for verification. Can be a string (key name) or a key object. Optional if a default is configured.
	 *
	 * @argument.algorithm The algorithm to use for verification. Optional; defaults to module setting or HS256.
	 *
	 * @argument.options Additional options for verification. Optional.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService			service		= ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );
		String				token		= StringCaster.cast( arguments.get( Key.of( "token" ) ) );
		java.security.Key	key			= resolveKey( service, arguments );
		String				algorithm	= resolveAlgorithm( service, arguments );
		IStruct				options		= getOptions( arguments );
		return service.verify( token, key, algorithm, options );
	}

	private java.security.Key resolveKey( JWTService service, ArgumentsScope arguments ) {
		Object keyArg = arguments.get( Key.of( "key" ) );
		if ( keyArg == null || "".equals( keyArg ) ) {
			String verifyKey = getDefaultSetting( service, KeyDictionary.defaultVerifyKey, "" );
			if ( !verifyKey.isEmpty() ) {
				return service.resolveVerificationKey( verifyKey );
			}
			String signKey = getDefaultSetting( service, KeyDictionary.defaultSigningKey, "" );
			if ( !signKey.isEmpty() && service.hasKey( signKey ) ) {
				return service.resolveVerificationKey( signKey );
			}
			throw new ortus.boxlang.jwt.exceptions.JWTKeyException(
			    "No key provided and no default verification key configured" );
		}
		if ( keyArg instanceof String keyStr && service.hasKey( keyStr ) ) {
			return service.resolveVerificationKey( keyStr );
		}
		String algorithm = resolveAlgorithm( service, arguments );
		return service.parseKey( keyArg, algorithm );
	}

	private String resolveAlgorithm( JWTService service, ArgumentsScope arguments ) {
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

	private IStruct getOptions( ArgumentsScope arguments ) {
		Object opts = arguments.get( Key.of( "options" ) );
		if ( opts instanceof IStruct s ) {
			return s;
		}
		return null;
	}

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
