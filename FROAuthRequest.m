//
//  FROAuthRequest.m
//  kroonjuwelen
//
//  Created by Jonathan Dalrymple on 12/04/2010.
//  Copyright 2010 Float:Right. All rights reserved.
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

-(BOOL) _startAsynchronousWithoutAuthentication;
-(void) _authenticationDidSucceed:(FROAuthRequest*) aRequest;
-(void) _authenticationDidFail:(FROAuthRequest*) aRequest;

@end

@interface ASIFormDataRequest(private)

-(id) postData;

@end

@implementation FROAuthRequest

@synthesize token = _token;
@synthesize consumer = _consumer;
@synthesize signatureProvider = _signatureProvider;
@synthesize requestTokenURL = _requestTokenURL;

#pragma mark -
#pragma mark Factory Methods
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


#pragma mark -
#pragma mark Init Methods
-(id) initWithURL: (NSURL *)newURL  
			consumer: (OAConsumer*) consumer
			   token: (OAToken*) token
			   realm: (NSString*) realm
   signatureProvider: (id<OASignatureProviding>) provider
{

	if( self = [super initWithURL: newURL] ){
		
		//Alter this after the request has been created;
		//[self setRequestMethod:@"POST"];
		_requestTokenURL = nil;
		
		[self setConsumer: consumer];
				
		if( token == nil ){
			self.token = [[OAToken alloc] init];
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
#pragma mark Start Methods
/*
 *	Overload start ASync
 *
 *	Decide whether we need to authenticate or not
 */
-(void) startAsynchronous{
	
	//If we dont have a token go and get one
	if( ![self hasAuthenticatedToken] ){
		
		FROAuthRequest		*authenticationRequest;
		
		authenticationRequest = [FROAuthRequest _accessTokenFromProvider: [NSURL URLWithString:@"http://twitter.com/oauth/request_token"] 
															WithUsername: @"veritech"//[self username] 
																password: @"robotech"//[self password]
															 andConsumer: [self consumer]	
		 ];
		
		[authenticationRequest setUserInfo:[NSDictionary dictionaryWithObject:self forKey:@"request"]];
		
		[authenticationRequest setDelegate:self];
		
		//Set the callbacks
		[authenticationRequest setDidFinishSelector:@selector(_authenticationDidSucceed:)];
		[authenticationRequest setDidFailSelector:@selector(_authenticationDidFail:)];
		
		//Call special method that skips this check
		[authenticationRequest _startAsynchronousWithoutAuthentication];
	}
	else{
		//We might want to load the token before this point
		[self _startAsynchronousWithoutAuthentication];
	}
	
}

/*
 *	Token Management
 *	Do we have an authenticated token
 *
 */
-(BOOL) hasAuthenticatedToken{
	
	OAToken	*authenticatedToken;
	
	NSLog(@"[FROAuthRequest hasAuthenticateToken] user: %@",[self username]);
	
	//Get the authenticatedToken
	authenticatedToken = [[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:@"twitter" 
																				prefix:[self username]
	];

	//Validate
	if( authenticatedToken ){
		
		NSLog(@"token key: %@", [authenticatedToken key]);
		NSLog(@"token secret: %@", [authenticatedToken secret]);
		//Set the token
		[self setToken: authenticatedToken];
		return YES;
	}
	else{
		return NO;
	}
}

/*
 *	Special method to skip authentication check
 */
-(BOOL) _startAsynchronousWithoutAuthentication{
	[self prepare];
	
	[super startAsynchronous];
}

/*
 *	Did Authenticate callback
 */
-(void) _authenticationDidSucceed:(FROAuthRequest*) aRequest{
	
	NSLog(@"Response %@",[aRequest responseString]);
	OAToken				*authenticatedToken;
	FROAuthRequest		*parentRequest;
	
	//Create a token with the request
	authenticatedToken = [[OAToken alloc] initWithHTTPResponseBody:[aRequest responseString]];
	
	//If there is no request token
	if( ![authenticatedToken key] ){
		
		//Cause the request to fail
		[self _authenticationDidFail:aRequest];
		return;
	}
	
	//Get the object from the userInfo
	if( ![aRequest userInfo] ){
		//NSLog(@"No userInfo");
		[NSException raise:@"InvalidUserInfo" format:@"No UserInfo set for %@ to %@",aRequest, [aRequest url]];
	}
	
	//Get the parent request
	if( ( parentRequest = [[aRequest userInfo] objectForKey:@"request"] ) ){		
		//Save the token with the username of the user
		//So we have one token per user
		//We should consider locking this just in case
		[authenticatedToken storeInUserDefaultsWithServiceProviderName:@"twitter" 
																prefix:[parentRequest username]
		];
		
		//Set the token to the new token
		[parentRequest setToken:authenticatedToken];
		
		//Start the request
		[parentRequest _startAsynchronousWithoutAuthentication];
	}
	
}

/*
 *	Did Fail callback
 */
-(void) _authenticationDidFail:(FROAuthRequest*) aRequest{
	NSLog(@"Hard Fail => HTTP Error:%d", [aRequest responseStatusCode]);
	
	FROAuthRequest	*parentRequest;
	
	//Call the parent failure method
	//Get the object from the userInfo
	if( ![aRequest userInfo] ){
		//NSLog(@"No userInfo");
		[NSException raise:@"InvalidUserInfo" format:@"No UserInfo set for %@ to %@",aRequest, [aRequest url]];
	}
	
	//Get the parent request
	if( ( parentRequest = [[aRequest userInfo] objectForKey:@"request"] ) ){
		
		//Call the parent tread failure method
		[[parentRequest delegate] performSelectorOnMainThread:[parentRequest didFailSelector] withObject:parentRequest waitUntilDone:YES];
	}
}


- (void)applyAuthorizationHeader{
	//NSLog(@"Test");
}

- (void)attemptToApplyCredentialsAndResume{
	
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

/*
 
 
- (void)requestFinished{
	
	NSLog(@"[FROAuthRequest] Request Finished");

	
	[super requestFinished];
}
*/ 
- (void)requestFailed:(FROAuthRequest *) pRequest{
#if DEBUG
	NSLog(@"[FROAuthRequest requestFailed] %@", [pRequest error]);
#endif
	//[super requestFinished];
}


//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//		OAuth Methods
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
#pragma mark -
#pragma mark Request Token
+(OAToken*) _requestTokenFromProvider:(NSURL*) requestURL 
					 withConsumer:(OAConsumer*) pConsumer 
						forObject:(id) pDelegate
{
	
#if DEBUG
	NSLog(@"[FROAuthRequest requestToken]");
#endif
	FROAuthRequest* tokenRequest;
	
	tokenRequest = [FROAuthRequest requestWithURL: requestURL 
										 consumer: pConsumer
											token: nil 
											realm: nil 
								signatureProvider: nil
					];
	
	[tokenRequest startSynchronous];
	
	return [FROAuthRequest _didRequestToken: tokenRequest forObject:pDelegate];
}

/*
 Request token callback
 */
+(OAToken*) _didRequestToken:(FROAuthRequest*) pRequest 
			   forObject:pDelegate
{

	OAToken *tempToken;
	
	//Parse out the token
	if( [pRequest responseString] && [pRequest responseStatusCode] == 200 ){
		
		tempToken = [[[OAToken alloc] initWithHTTPResponseBody: [pRequest responseString]] autorelease];
#if DEBUG
		NSLog(@"[FROAuthRequest didRequestToken] Found a response \r\n%@", [pRequest responseString]);

		NSLog(@"[FROAuthRequest didRequestToken] New Request Token Created key:%@ secret:%@",tempToken.key,tempToken.secret);
#endif
		//Authenticate the token
		if( [tempToken key] != nil){

			if( pDelegate && [pDelegate respondsToSelector:@selector(authenticateToken:withProvider:)]){
				
				[pDelegate performSelector:@selector( authenticateToken:withProvider:) withObject: tempToken withObject: [pRequest url]];
				//[pDelegate authenticateToken: tempToken withProvider:[pRequest url]];

			}
			
			return tempToken;			
		} 
	}
	else{
		
		UIAlertView *alertView;
		
		alertView = [[UIAlertView alloc] initWithTitle: NSLocalizedString(@"Could not connect",@"Could not connect")
											   message: NSLocalizedString(@"Could not to connect to the internet",@"Could not to connect to the internet")
											  delegate: nil
									 cancelButtonTitle: NSLocalizedString(@"ok",@"Ok")
									 otherButtonTitles: nil
					 ];
		
		[alertView show];
		
		[alertView release];
#if DEBUG		
		NSLog(@"[FROAuthRequest didRequestToken] failed");
#endif
	}

	//Notify the parent that we failed
	//[[self delegate] performSelectorOnMainThread:[self didFailSelector] withObject:self waitUntilDone:[NSThread isMainThread]];		
	
	return nil;
}


#pragma mark -
#pragma mark Authorize Token
+(OAToken*) _accessTokenWithRequestToken:(OAToken*) pToken 
						fromProvider:(NSURL*) accessURL 
						 forConsumer:(OAConsumer*) pConsumer
						   forObject:(id) pDelegate
{

#if DEBUG
	NSLog(@"[FROAuthRequest authorizeToken]");
#endif
	FROAuthRequest* authorizeRequest;
	
	//Append the pin to the token
	//NSString *URLStr = [accessURL absoluteString];
	
	//URLStr = [URLStr stringByAppendingString:[NSString stringWithFormat:@"?oauth_verifier=%s", pToken.pin]];
	
	authorizeRequest = [FROAuthRequest requestWithURL: accessURL //[NSURL URLWithString:URLStr]
											 consumer: pConsumer
												token: pToken 
												realm: nil 
									signatureProvider: nil
						];

	//We are already operating on a seperate thread so using this should be fine
	[authorizeRequest startSynchronous];
	
	//This log can be split into callbacks
	if( [authorizeRequest responseStatusCode] == 200 && [authorizeRequest responseString] ){
#if DEBUG
		NSLog(@"[FROAuthRequest] Created new Access Token! \r\n%@", [authorizeRequest responseString]);
#endif
		//Set the access token
		return [[[OAToken alloc] initWithHTTPResponseBody:[authorizeRequest responseString]] autorelease];

	}
	else{
#if DEBUG
		NSLog(@"[FROAuthRequest] Failed to get Access Token!");
#endif	
		return nil;
	}
}

//Use xAuth to authorize a token
+(FROAuthRequest*) _accessTokenFromProvider:(NSURL*) accessURL 
						WithUsername:(NSString*) pUsername 
							password:(NSString*) pPassword
						 andConsumer:(OAConsumer*) pConsumer
{
	
	FROAuthRequest *accessRequest;
	
	//Insure that it SSL
	if( ![[accessURL scheme] isEqualToString:@"https"] ){
#if DEBUG
		NSLog(@"Not SSL :%@",[accessURL scheme]);
#endif		
		//return nil;
	}
	
	accessRequest = [FROAuthRequest requestWithURL: accessURL 
										  consumer: pConsumer 
											 token: nil  
											 realm: nil 
								 signatureProvider: nil
					 ];
	
	[accessRequest setRequestMethod:@"POST"];
	
	[accessRequest setPostValue:pUsername forKey:@"x_auth_username"];
	
	[accessRequest setPostValue:pPassword forKey:@"x_auth_password"];
	
	[accessRequest setPostValue:@"client_auth" forKey:@"x_auth_mode"];
	
	
	return accessRequest;
	//[accessRequest startAsynchronous];
	
	//[accessRequest ]
	/*
	if( [accessRequest responseStatusCode] == 200 && [accessRequest responseString] ){
#if DEBUG
		NSLog(@"[FROAuthRequest xAuthToken] Success \r\n%@", [accessRequest responseString]);
#endif		
		return [[[OAToken alloc] initWithHTTPResponseBody:[accessRequest responseString]] autorelease];
	}
	else{
		
#if DEBUG
		NSLog(@"[FROAuthRequest xAuthToken] Failure \r\n%@", [accessRequest error]);
#endif		
		return nil;
	}
	*/
}

//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//			Utilites
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-

/*
 URL encode a string
 */
- (NSString *) URLEncodedString: (NSString *) string {

	NSString *result = (NSString *)CFURLCreateStringByAddingPercentEscapes(NULL, 
																		   (CFStringRef)string, 
																		   NULL, 
																		   (CFStringRef)@":/=,!$&'()*+;[]@#?",
																		   kCFStringEncodingUTF8);
#if DEBUG
	NSLog(@"String encoded \r\nin:%@ \r\nout:%@", string, result);
#endif
	
    return [result autorelease];
}

//Create a url string
- (NSString *)URLStringWithoutQueryFromURL: (NSURL *) pURL
{
    NSArray *parts = [[pURL absoluteString] componentsSeparatedByString:@"?"];
    return [parts objectAtIndex:0];
}

/*
 Generate a timestamp on demand
 */
- (NSString*)timestamp 
{
	if(!_timestamp) {
		_timestamp = [NSString stringWithFormat:@"%d", time(NULL)];
	}
	
    return _timestamp;
}

//Generate Nonce on demand
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

//Create BaseString
- (NSString *)signatureBaseString 
{
	
	NSMutableDictionary	*params;
	NSString		*queryStr;
	//NSArray			*queryParams;
	
	params = [NSMutableDictionary dictionaryWithObjectsAndKeys:
							[[self consumer] key],
							@"oauth_consumer_key",
							[[self token] key] ? [[self token] key] : @"",	//Stops nil from being entered and causing a failure
							@"oauth_token",
							[[self signatureProvider] name],
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
		
		for( NSString *key in [self postData] ){
			
			[params setValue:[[self postData] objectForKey:key] forKey:key];
		}
		
	}
	
	
	return [self signatureBaseStringForURL: [self url] 
								withMethod: [self requestMethod] 
								withParams: (NSDictionary*)params
			];
}

//Create a signature base string
-(NSString*) signatureBaseStringForURL:(NSURL*) pURL 
							withMethod:(NSString*) method 
							withParams:(NSDictionary*) dictionary{
	
	NSMutableArray *pairs;
	NSArray *sortedPairs;
	NSString *key, *tmp;
	NSString *baseString, *normalizedString;
	
	if( [dictionary count] < 6 ){
		@throw [NSException exceptionWithName:@"InvalidParameterCount" 
									   reason:[NSString stringWithFormat:@"Passed Dictionary contains too few entries (6 Min vs %d found)", [dictionary count]] 
									 userInfo:[NSDictionary dictionaryWithObjectsAndKeys: dictionary,@"dictionary",self,@"request",nil]];
	}
	
	pairs = [[NSMutableArray alloc] init];
	
	for( key in dictionary ){
		
		if( [[dictionary objectForKey:key] length] > 0){
			tmp = [NSString stringWithFormat:@"%@=%@", key, [self URLEncodedString: [dictionary objectForKey:key] ]];
			
			//tmp = [self URLEncodedString: tmp];
			
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
	
	baseString = [NSString stringWithFormat:@"%@&%@&%@",
					 [method uppercaseString],
					 [self URLEncodedString:[self URLStringWithoutQueryFromURL:pURL]],
					 [self URLEncodedString: normalizedString]
				  ];
	
	//Cleanup
	[pairs release];
#if DEBUG
	NSLog(@"Basestring \r\n%@", baseString);
#endif	
	return baseString;
}

//Add Auth header to this request
- (void)prepare 
{
    // sign
	// Secrets must be urlencoded before concatenated with '&'
	// TODO: if later RSA-SHA1 support is added then a little code redesign is needed
	NSString	*consumerSecret, *tokenSecret, *signature, *oauthToken, *oauthHeader;

	consumerSecret = [self URLEncodedString: self.consumer.secret];
	
	tokenSecret = [self URLEncodedString: self.token.secret];

    signature = [self.signatureProvider signClearText:[self signatureBaseString]
                                      withSecret:[NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret]];
    
    // set OAuth headers

    if ([self.token.key isEqualToString:@""]){
		oauthToken = @""; // not used on Request Token transactions
	}
    else{
		oauthToken = [NSString stringWithFormat:@"oauth_token=\"%@\", ", [self URLEncodedString: self.token.key]];
	}
    
    oauthHeader = [NSString stringWithFormat:
							 @"OAuth realm=\"%@\", oauth_consumer_key=\"%@\", %@oauth_signature_method=\"%@\", oauth_signature=\"%@\", oauth_timestamp=\"%@\", oauth_nonce=\"%@\", oauth_version=\"1.0\"",
                             [self URLEncodedString: _realm],
                             [self URLEncodedString: [self.consumer key]],
                             oauthToken,
                             [self URLEncodedString: [self.signatureProvider name]],
                             [self URLEncodedString: signature],
                             [self timestamp],
                             [self nonce]
							 ];
	
	if (self.token.pin.length) oauthHeader = [oauthHeader stringByAppendingFormat: @", oauth_verifier=\"%@\"", self.token.pin];					//added for the Twitter OAuth implementation
#if DEBUG
	NSLog(@"[FROAuthRequest prepare] \r\nAuthentication Header %@", oauthHeader);
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
	
	[_nonce release];
	
	// Cause a crash if if a nil check is done
	//[_timestamp release];

	[_consumer release];
	
	[_requestTokenURL release];
	
	[self.signatureProvider release];
	
	[self.token release];
	
	[super dealloc];
}

@end
