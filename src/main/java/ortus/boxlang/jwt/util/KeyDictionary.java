/**
 * [BoxLang]
 *
 * Copyright [2026] [Ortus Solutions, Corp]
 *
 * Licensed under the BoxLang Plus Subscription License.
 * ----------------------------------------------------------------------------------
 */

/**
 * Central registry of BoxLang {@code Key} constants used throughout the
 * bx-jwt module. Avoids stringly-typed lookups in structs and scopes.
 */
package ortus.boxlang.jwt.util;

import ortus.boxlang.runtime.scopes.Key;

/**
 * This class is used to store all the keys used in the dictionary for this module.
 */
public class KeyDictionary {

	public static final Key	algorithm				= new Key( "algorithm" );
	public static final Key	claims					= new Key( "claims" );
	public static final Key	clockSkew				= new Key( "clockSkew" );
	public static final Key	defaultAlgorithm		= new Key( "defaultAlgorithm" );
	public static final Key	defaultDecryptionKey	= new Key( "defaultDecryptionKey" );
	public static final Key	defaultEncAlgorithm		= new Key( "defaultEncAlgorithm" );
	public static final Key	defaultEncryptionKey	= new Key( "defaultEncryptionKey" );
	public static final Key	defaultKeyAlgorithm		= new Key( "defaultKeyAlgorithm" );
	public static final Key	defaultSigningKey		= new Key( "defaultSigningKey" );
	public static final Key	defaultVerifyKey		= new Key( "defaultVerifyKey" );
	public static final Key	encAlgorithm			= new Key( "encAlgorithm" );
	public static final Key	generateIat				= new Key( "generateIat" );
	public static final Key	generateJti				= new Key( "generateJti" );
	public static final Key	headers					= new Key( "headers" );
	public static final Key	iat						= new Key( "iat" );
	public static final Key	isValidLicense			= new Key( "isValidLicense" );
	public static final Key	jwk						= new Key( "jwk" );
	public static final Key	jti						= new Key( "jti" );
	public static final Key	JWTService				= new Key( "JWTService" );
	public static final Key	key						= new Key( "key" );
	public static final Key	keyAlgorithm			= new Key( "keyAlgorithm" );
	public static final Key	keys					= new Key( "keys" );
	public static final Key	moduleName				= new Key( "bxjwt" );
	public static final Key	options					= new Key( "options" );
	public static final Key	payload					= new Key( "payload" );
	public static final Key	privateKey				= new Key( "privateKey" );
	public static final Key	publicKey				= new Key( "publicKey" );
	public static final Key	secret					= new Key( "secret" );
	public static final Key	token					= new Key( "token" );
	public static final Key	validateClaims			= new Key( "validateClaims" );

}