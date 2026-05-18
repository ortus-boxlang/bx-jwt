/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 * BoxLang BIF that creates and returns a {@code JwtBuilder} BoxLang class
 * instance pre-seeded with the {@code JWTService} for fluent JWT construction.
 */
package ortus.boxlang.jwt.bifs;

import ortus.boxlang.jwt.services.JWTService;
import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.bifs.global.system.CreateObject;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.interop.DynamicInteropService;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Struct;

@BoxBIF( description = "Creates and returns a JwtBuilder BoxLang class instance pre-seeded with the JWTService for fluent JWT construction." )
public class JwtNew extends BIF {

	/**
	 * Creates and returns a JwtBuilder BoxLang class instance pre-seeded with the JWTService for fluent JWT construction.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF. (No arguments required for this BIF.)
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		JWTService		service		= ( JWTService ) context.getRuntime().getGlobalService( KeyDictionary.JWTService );

		ArgumentsScope	createArgs	= new ArgumentsScope();
		createArgs.put( Key.of( "type" ), "class" );
		createArgs.put( Key.of( "className" ), "bxModules.bxjwt.models.JwtBuilder" );
		createArgs.put( Key.of( "properties" ), new Struct() );

		CreateObject	createObject	= new CreateObject();
		Object			builder			= createObject.invoke( context, createArgs );

		DynamicInteropService.dereferenceAndInvoke( null, builder, context, Key.of( "init" ), new Object[] { service }, false );

		return builder;
	}

}
