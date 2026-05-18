/**
 * [BoxLang]
 *
 * Copyright [2025] [Ortus Solutions, Corp]
 */
package ortus.boxlang.jwt.interceptors;

import ortus.boxlang.jwt.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.dynamic.casters.BooleanCaster;
import ortus.boxlang.runtime.events.BaseInterceptor;
import ortus.boxlang.runtime.events.InterceptionPoint;
import ortus.boxlang.runtime.interop.DynamicInteropService;
import ortus.boxlang.runtime.services.IService;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

public class LicenseInterceptor extends BaseInterceptor {

	/**
	 * Interceptor to check for Boxlang+ (bx-plus) license on runtime start.
	 *
	 * Note: This interception will not fire during unit tests due to the module
	 * registration occurring after runtime start.
	 */
	@InterceptionPoint
	public void onRuntimeStart( IStruct data ) {
		BoxRuntime	runtime			= BoxRuntime.getInstance();
		IService	licenseService	= runtime.getGlobalService( "BoxlangLicenseService" );
		if ( licenseService == null ) {
			throw new BoxRuntimeException(
			    "The Boxlang+ (bx-plus) module is required to use this module. Please install and restart" );
		} else {
			try {
				Boolean isLicensed = BooleanCaster
				    .cast(
				        DynamicInteropService.dereferenceAndInvoke(
				            null,
				            licenseService,
				            runtime.getRuntimeContext(),
				            KeyDictionary.isValidLicense,
				            new Object[] {},
				            false
				        )
				    );
				if ( !isLicensed ) {
					throw new BoxRuntimeException(
					    "A valid license or trial mode for the Boxlang+ (bx-plus) module is required to use this module. Please check your logs" );
				}
			} catch ( Exception e ) {
				throw new BoxRuntimeException( "Error checking Boxlang+ (bx-plus) license: " + e.getMessage(), e );
			}

		}
	}

}
