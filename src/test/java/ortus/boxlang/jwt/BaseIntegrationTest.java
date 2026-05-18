/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */

/**
 * Base class for non-web integration tests. Bootstraps the BoxLang runtime,
 * loads the bx-jwt module from the build directory, and sets up a fresh
 * {@code ScriptingRequestBoxContext} before each test method.
 */
package ortus.boxlang.jwt;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.context.ScriptingRequestBoxContext;
import ortus.boxlang.runtime.modules.ModuleRecord;
import ortus.boxlang.runtime.scopes.IScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.scopes.VariablesScope;
import ortus.boxlang.runtime.services.ModuleService;

/**
 * Use this as a base integration test for your non web-support package
 * modules. If you want web based testing, use the BaseWebIntegrationTest
 */
public abstract class BaseIntegrationTest {

	protected static BoxRuntime				runtime;
	protected static ModuleService			moduleService;
	protected static ModuleRecord			moduleRecord;
	protected static Key					result		= new Key( "result" );
	protected static Key					moduleName	= KeyDictionary.moduleName;
	protected ScriptingRequestBoxContext	context;
	protected IScope						variables;

	@BeforeAll
	public static void setup() {
		runtime			= BoxRuntime.getInstance( true, Path.of( "src/test/resources/boxlang.json" ).toString() );
		moduleService	= runtime.getModuleService();
		// Load the module
		loadModule( runtime.getRuntimeContext() );
	}

	@BeforeEach
	public void setupEach() {
		// Create the mock contexts
		context		= new ScriptingRequestBoxContext();
		variables	= context.getScopeNearby( VariablesScope.name );
	}

	protected static void loadModule( IBoxContext context ) {
		if ( !runtime.getModuleService().hasModule( moduleName ) ) {
			System.out.println( "Loading module: " + moduleName );
			String physicalPath = Paths.get( "./build/module" ).toAbsolutePath().toString();
			moduleRecord = new ModuleRecord( physicalPath );

			moduleService.getRegistry().put( moduleName, moduleRecord );

			moduleRecord
			    .loadDescriptor( context )
			    .register( context )
			    .activate( context );
		} else {
			System.out.println( "Module already loaded: " + moduleName );
		}
	}

}
