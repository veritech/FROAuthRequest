//
//  FROAuthRequest.m
//
// Copyright (C) 2011-2012 Jonathan Dalrymple
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to 
// deal in the Software without restriction, including without limitation the 
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
// sell copies of the Software, and to permit persons to whom the Software is 
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
// IN THE SOFTWARE.

//

#import "FROAuthRequest.h"

@interface FROAuthRequest(private)

- (void) prepare;
- (NSString *)signatureBaseString;
- (NSString*) signatureBaseStringForURL:(NSURL*) pURL 
							withMethod:(NSString*) method 
							withParams:(NSDictionary*) dictionary;
- (NSString *)timestamp;
- (NSString *)nonce;

@end

@interface ASIFormDataRequest(private)

-(id) postData;

@end

@implementation FROAuthRequest

@synthesize token = _token;
@synthesize consumer = _consumer;
@synthesize signatureProvider = _signatureProvider;

#pragma mark -
#pragma mark OAuth authentication helper methods
/**
 *	Request a token from a provider
 */
+(void) requestTokenFromProvider:(NSURL*) aURL 
					withConsumer:(OAConsumer*) aConsumer
				   OAuthCallback:(NSString*) aCallback
						delegate:(id<FROAuthenticationDelegate>) aDelegate
{

	FROAuthRequest	*req;
	
	req = [FROAuthRequest requestWithURL:aURL 
								consumer:aConsumer 
								   token:nil 
								   realm:nil 
					   signatureProvider:nil
		   ];
	
	[req setRequestMethod:@"POST"];
	//TODO:
	//Assign self as delegatea
	
	if( aCallback ){
		//[req addPostValue:@"sotm://oauth-authenticated" forKey:@"oauth_callback"];
		[req addPostValue:aCallback 
				   forKey:@"oauth_callback"
		 ];
	}

	//The completion block
	[req setCompletionBlock:^{
		#if DEBUG
			NSLog(@"[FROAuthRequest requestAuthorizedTokenFromProvider] Complete\r\n%@",[req responseString]);		
		#endif
		
		OAToken	*requestToken = [[OAToken alloc] initWithHTTPResponseBody:[req responseString]];
		SEL		selector = @selector(OAuthRequest:didReceiveRequestToken:);
		

		if( [aDelegate respondsToSelector:selector] ){
			[aDelegate performSelector:selector 
							withObject:req
							withObject:requestToken
			 ];
		}
		
		[requestToken release];
		
	}];
	
	//Set the failed block
	[req setFailedBlock:^{
		
		#if DEBUG
			NSLog(@"[FROAuthRequest requestAuthorizedTokenFromProvider] Failure \r\n%@",req);	
		#endif
		
		SEL selector = @selector(OAuthRequest:didFailWithError:);
		
		if( [aDelegate respondsToSelector:selector] ){
			[aDelegate performSelector:selector 
							withObject:[req error]
			 ];
		}
	}];
	
	[req startAsynchronous];
}


/**
 *	Attempt to get an authorized token
 */
+(void) requestAuthorizedTokenFromProvider:(NSURL*) aURL 
							  withConsumer:(OAConsumer*) aConsumer 
							  requestToken:(OAToken*) aToken 
								  delegate:(id<FROAuthenticationDelegate>) aDelegate
{

	FROAuthRequest	*req;
	
	req = [FROAuthRequest requestWithURL:aURL
								consumer:aConsumer
								   token:aToken
								   realm:nil
					   signatureProvider:nil
		   ];

	[req setRequestMethod:@"POST"];
	
	//Set the completion block
	[req setCompletionBlock:^{		
		
		#if DEBUG
			NSLog(@"[FROAuthRequest requestAuthorizedTokenFromProvider] Complete\r\n%@",[req responseString]);		
		#endif
	
		OAToken	*authToken = [[OAToken alloc] initWithHTTPResponseBody:[req responseString]];
		SEL		selector = @selector(OAuthRequest:didReceiveAuthorizedToken:);
		
		if( [aDelegate respondsToSelector:selector]){
		
			[aDelegate performSelector:selector
							withObject:req
							withObject:authToken
			 ];
			
		}
		
		//DebugLog(@"The delegate %@", aDelegate);
		[authToken release];
	}];
	
	[req setFailedBlock:^{
		
		#if DEBUG
			NSLog(@"[FROAuthRequest requestAuthorizedTokenFromProvider] Failure \r\n%@",req);
		#endif
	
		SEL selector = @selector(OAuthRequest:didFailWithError:);
		
		if( [aDelegate respondsToSelector:selector] ){
			[aDelegate performSelector:selector 
							withObject:[req error]
			 ];
		}
		
	}];
	
	[req startAsynchronous];
}

#pragma mark -
#pragma mark Object creation Methods
/**
 *	OAuth factory request
 */
+(id) requestWithURL: (NSURL *)newURL  
			consumer: (OAConsumer*) consumer
			   token: (OAToken*) token
			   realm: (NSString*) realm
   signatureProvider: (id<OASignatureProviding>) provider
{	
	return [[[FROAuthRequest alloc] initWithURL: newURL 
									   consumer: consumer 
										  token: token 
										  realm: realm 
							  signatureProvider: provider
			 ] autorelease];
}


/**
 *	O
 */
-(id) initWithURL: (NSURL *)newURL  
			consumer: (OAConsumer*) consumer
			   token: (OAToken*) token
			   realm: (NSString*) realm
   signatureProvider: (id<OASignatureProviding>) provider
{

	if( self = [super initWithURL: newURL] ){
		
		//Alter this after the request has been created;
		//[self setRequestMethod:@"POST"];
		
		[self setConsumer: consumer];
				
		if( token == nil ){
			self.token = [[OAToken alloc] initWithKey:@"" secret:@""];
		}
		else{
			self.token = token;
		}
		
		_realm = realm ? [realm retain] : @"";
		
		if( provider == nil ){
			
			self.signatureProvider = [[OAHMAC_SHA1SignatureProvider alloc] init];
		}
		else{
			self.signatureProvider = provider;
		}
		
		_nonce = nil;
		
		_timestamp = nil;
	
	}
	
	return self;
	
}


#pragma mark -
#pragma mark ASIHTTPRequest inards
-(void) startAsynchronous{
	
	[self prepare];
	
	[super startAsynchronous];
}

-(void) startSynchronous{
	[self prepare];
	
	[super startSynchronous];
}

-(void) start{
	[self prepare];
	
	[super start];
}

- (void)applyAuthorizationHeader{
#if DEBUG
	NSLog(@"[FROAuthRequest] applyAuthorizationHeader");
#endif
}

- (void)attemptToApplyCredentialsAndResume{
#if DEBUG
	NSLog(@"[FROAuthRequest] attemptToApplyCredentialsAndResume %d\r\n==== Response ====\r\n%@", [self responseStatusCode],[self responseString]);
#endif
}

#pragma mark -
#pragma mark Overloaded ASIFormDataRequest
- (void)buildPostBody
{
	//If we want to do anything other than GET, build a body
	if(![[self requestMethod] isEqualToString:@"GET"]){
		[super buildPostBody];
	}
	
}

- (void)requestFinished{
	[super requestFinished];
#if DEBUG
	NSLog(@"[FROAuthRequest] Request Finished");
#endif

}

- (void)failWithError:(NSError *)theError{
	[super failWithError:theError];
#if DEBUG
	NSLog(@"[FROAuthRequest requestFailed] %@ %@", theError, [self responseString]);
#endif

}

#pragma mark -
#pragma mark OAuth Utilites
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//			OAUTH Utilites
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
/**
 *	Generate a timestamp on demand
 */
- (NSString*)timestamp 
{
	if(!_timestamp) {
		_timestamp = [NSString stringWithFormat:@"%d", time(NULL)];
		[_timestamp retain];
	}
	
    return _timestamp;
}

/**
 *	Generate Nonce on demand
 */
- (NSString*)nonce 
{
	
	if( !_nonce ){
		CFUUIDRef theUUID = CFUUIDCreate(NULL);
		CFStringRef string = CFUUIDCreateString(NULL, theUUID);
		CFRelease(theUUID);
		
		_nonce = (NSString *)string;
	}

    return _nonce;
}

/**
 *	Create BaseString
 */
- (NSString *)signatureBaseString 
{
	
	NSMutableDictionary	*params;
	NSString		*queryStr;
	//NSArray			*queryParams;
	
	params = [NSMutableDictionary dictionaryWithObjectsAndKeys:
							[[[self consumer] key] encodedURLParameterString],
							@"oauth_consumer_key",
							([[self token] key] ? [[[self token] key] encodedURLParameterString] : @""),	//Stops nil from being entered and causing a failure
							@"oauth_token",
							[[[self signatureProvider] name] encodedURLParameterString],
							@"oauth_signature_method",
							[self timestamp],
							@"oauth_timestamp",
							[self nonce],
							@"oauth_nonce",
							@"1.0",
							@"oauth_version",
							nil
							];
		
	//Find out if the params to the query
	if( queryStr = [[self url] query] ){
		//Break the query up into pairs and add them to the dictionary
		for( NSString *keyValPairStr in [queryStr componentsSeparatedByString:@"&"]){
			
			//NSLog(@"KeyVal Pair %@", keyValPairStr );
			
			NSArray *keyValPair = [keyValPairStr componentsSeparatedByString:@"="];
			
			[params setObject: [keyValPair objectAtIndex:1] forKey: [keyValPair objectAtIndex:0]];
		}
		
	}
	
	//If this is post request find out
	if( [self isKindOfClass:[ASIFormDataRequest class]] && [self respondsToSelector:@selector(postData)]){
		
		for( NSDictionary *pairDict in [self postData] ){
			DebugLog(@"kv %@", pairDict);						
			
			[params setValue:[pairDict objectForKey:@"value"] 
					  forKey:[pairDict objectForKey:@"key"]
			 ];
			
			

			//Loop over the dictionary
			//[params setValue:[pairDict objectForKey:key] forKey:key];
		}
		
	}
	
	
	return [self signatureBaseStringForURL: [self url] 
								withMethod: [self requestMethod] 
								withParams: (NSDictionary*)params
			];
}

/**
 *	Create a signature base string
 */
-(NSString*) signatureBaseStringForURL:(NSURL*) pURL 
							withMethod:(NSString*) method 
							withParams:(NSDictionary*) dictionary{
	
	NSMutableArray *pairs;
	NSArray *sortedPairs;
	NSString *key, *tmp, *val;
	NSString *baseString, *normalizedString;
	
#if DEBUG
	NSLog(@"==== Basestring Input ====\r\n%@", dictionary);
#endif
	
	pairs = [[NSMutableArray alloc] initWithCapacity:[dictionary count]];
	
	// OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
	for( key in dictionary ){
		
		val = [dictionary objectForKey:key];
		
		if( [val length] > 0){
			tmp = [NSString stringWithFormat:@"%@=%@", key, [val encodedURLParameterString]];
			
			[pairs addObject:tmp];			
		}
		else{
			#if DEBUG
			NSLog(@"[FRORequest signatureBaseString] %@ was nil, skipping", key);
			#endif
		}

	}
	
	sortedPairs = [pairs sortedArrayUsingSelector:@selector(compare:)];

	normalizedString = [sortedPairs componentsJoinedByString:@"&"];

    // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"
	baseString = [NSString stringWithFormat:@"%@&%@&%@",
						[method uppercaseString],
						[[pURL URLStringWithoutQuery] encodedURLParameterString],
						[normalizedString encodedURLString]
				  ];
	
	//Cleanup
	[pairs release];
#if DEBUG
	NSLog(@"==== Basestring ====\r\n%@", baseString);
#endif	
	return baseString;
}

//Add Auth header to this request
- (void)prepare 
{
    // sign
	// Secrets must be urlencoded before concatenated with '&'
	NSString	*consumerSecret, *tokenSecret, *signature, *oauthToken, *oauthHeader;

	consumerSecret = [[self consumer] secret];
	
	//Ensure the token secret is at least empty and not nil
	if( ![[self token] secret] ){
		tokenSecret = @"";
	}
	else{
		tokenSecret = [[self token] secret];
	}

    signature = [[self signatureProvider] signClearText:[self signatureBaseString]
											 withSecret:[NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret]];
    
    // set OAuth headers

    if( ![[self token] key] || [[[self token] key] isEqualToString:@""] ){
		oauthToken = @""; // not used on Request Token transactions
	}
    else{
		oauthToken = [NSString stringWithFormat:@"oauth_token=\"%@\", ", [[[self token] key] encodedURLString]];
	}
    
    oauthHeader = [NSString stringWithFormat:
							 @"OAuth realm=\"%@\", oauth_consumer_key=\"%@\", %@oauth_signature_method=\"%@\", oauth_signature=\"%@\", oauth_timestamp=\"%@\", oauth_nonce=\"%@\", oauth_version=\"1.0\"",
                             [_realm encodedURLString],
                             [[[self consumer] key] encodedURLString],
                             oauthToken,
                             [[[self signatureProvider] name] encodedURLString],
                             [signature encodedURLString],
                             [self timestamp],
                             [self nonce]
						];
	
	//No longer supports pin
#if DEBUG
	NSLog(@"[FROAuthRequest prepare] \r\n==== Authentication Header ====\r\n%@", oauthHeader);
#endif	
	[self addRequestHeader:@"Authorization" value: oauthHeader];
	
	//Hack --> set the username and password to nil
	[self setUsername:nil]; [self setPassword:nil];
}


#pragma mark -
#pragma mark Dealloc
-(void) dealloc{
/*	
	[self.requestToken release];
*/
	[_realm release];
	
	// _nonce was created by CF functions, so use CFRelease in case we are in garbage collected environment
	if (_nonce) {
		CFRelease((CFStringRef) _nonce);
	}
	
	[_timestamp release];

	[_consumer release];
	
	[_signatureProvider release];
	
	[_token release];
	
	[super dealloc];
}

@end
