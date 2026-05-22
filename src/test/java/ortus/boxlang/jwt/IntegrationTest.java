/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */

/**
 * Integration tests for module bootstrap and cross-cutting module behavior.
 */
package ortus.boxlang.jwt;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class IntegrationTest extends BaseIntegrationTest {

	@DisplayName( "Test the module loads in BoxLang" )
	@Test
	public void testModuleLoads() {
		assertThat( moduleService.getRegistry().containsKey( moduleName ) ).isTrue();
		assertThat( runtime.getGlobalService( "JWTService" ) ).isNotNull();
	}

	@DisplayName( "Key registry: remove key" )
	@Test
	public void testKeyRegistryRemove() {
		runtime.executeSource(
		    """
		    jwtService = getBoxContext().getRuntime().getGlobalService( "JWTService" );
		    jwtService.registerKey(
		        "temp-key",
		        { algorithm: "HS256", secret: "abcdefghijklmnopqrstuvwxyz12345" }
		    );
		    hadKey = jwtService.hasKey( "temp-key" );
		    jwtService.removeKey( "temp-key" );
		    hasKeyAfterRemove = jwtService.hasKey( "temp-key" );
		    result = hadKey && !hasKeyAfterRemove;
		    """,
		    context
		);
		assertThat( ( Boolean ) variables.get( "result" ) ).isTrue();
	}

}
