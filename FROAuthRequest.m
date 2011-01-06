//
//  FROAuthRequest.m
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

@end

@interface ASIFormDataRequest(private)

-(id) postData;

@end

@implementation FROAuthRequest

@synthesize token = _token;
@synthesize consumer = _consumer;
@synthesize signatureProvider = _signatureProvider;

#pragma mark -
#pragma mark Factory Methods
/**
 *	A standard OAuth request
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
 *	Request a token from a provider
 */
+(void) requestTokenFromProvider:(NSURL*) aURL 
				  withConsumer:(OAConsumer*) aConsumer 
				  withDelegate:(id<FROAuthenticationDelegate>) aDelegate{

	FROAuthRequest	*req;
	
	req = [FROAuthRequest requestWithURL:aURL 
								consumer:aConsumer 
								   token:nil 
								   realm:nil 
					   signatureProvider:nil
		   ];
	
	[req setDelegate:self];
	
	[req setDidFinishSelector:@selector(OAuthRequestDidReceiveRequestToken:)];
	[req setDidFailSelector:@selector(OAuthRequestDidFail:)];
	
	[req startAsynchronous];
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


-(void) startAsynchronous{
	[self prepare];
	
	[super startAsynchronous];
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

//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//			OAUTH Utilites
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-

/*
 URL encode a string
 */
- (NSString *) URLEncodedString: (NSString *) aString {

	NSString *result = [aString encodedURLString];
#if DEBUG
	NSLog(@"==== String encoded ====\r\nin:%@\r\nout:%@", aString, result);
#endif
	
    return result; //[result autorelease];
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
	
	//[_nonce release];
	
	// Cause a crash if if a nil check is done
	//[_timestamp release];

	[_consumer release];
	
	[_signatureProvider release];
	
	[_token release];
	
	[super dealloc];
}

@end
