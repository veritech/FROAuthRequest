//
//  FRXAuthRequest.m
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

#import "FRXAuthRequest.h"

@interface FRXAuthRequest(private)

-(void) _startAsynchronousWithoutAuthentication;
-(void) _authenticationDidSucceed:(FRXAuthRequest*) aRequest;
-(void) _authenticationDidFail:(FRXAuthRequest*) aRequest;

-(BOOL) hasAuthenticatedToken;

+(FRXAuthRequest*) _accessTokenFromProvider:(NSURL*) accessURL 
							   WithUsername:(NSString*) pUsername 
								   password:(NSString*) pPassword
								andConsumer:(OAConsumer*) pConsumer;

- (void)prepare;

@end

@implementation FRXAuthRequest


//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//		OAuth Methods
//-**-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**-*-*-*-*-*-*-*-*-*-
//Use xAuth to authorize a token
+(FRXAuthRequest*) _accessTokenFromProvider:(NSURL*) accessURL 
							   WithUsername:(NSString*) pUsername 
								   password:(NSString*) pPassword
								andConsumer:(OAConsumer*) pConsumer
{
	
	FRXAuthRequest *accessRequest;
	
	//Insure that it SSL
	if( ![[accessURL scheme] isEqualToString:@"https"] ){
#if DEBUG
		NSLog(@"Not SSL :%@",[accessURL scheme]);
#endif		
		//return nil;
	}
	
	accessRequest = [FRXAuthRequest requestWithURL: accessURL 
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
}

#pragma mark -
#pragma mark Token Management
/*
 *	Token Management
 *	Do we have an authenticated token
 *
 */
-(BOOL) hasAuthenticatedToken{
	
	OAToken	*authenticatedToken;
	
	NSLog(@"[FROAuthRequest hasAuthenticateToken] user: %@",[self username]);
	
	//Get the authenticatedToken
	authenticatedToken = [[[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:@"twitter" 
																				prefix:[self username]
						  ] autorelease];
	
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
		
		FRXAuthRequest		*authenticationRequest;
		
		authenticationRequest = [FRXAuthRequest _accessTokenFromProvider: [NSURL URLWithString:[self requestTokenURL]] 
															WithUsername: [self username] 
																password: [self password]
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
 *	Special method to skip authentication check
 */
-(void) _startAsynchronousWithoutAuthentication{
	[self prepare];
	
	[super startAsynchronous];
}


/*
 *	Did Authenticate callback
 */
-(void) _authenticationDidSucceed:(FRXAuthRequest*) aRequest{
	
	NSLog(@"Response %@",[aRequest responseString]);
	OAToken				*authenticatedToken;
	FRXAuthRequest		*parentRequest;
	
	//Create a token with the request
	authenticatedToken = [[[OAToken alloc] initWithHTTPResponseBody:[aRequest responseString]] autorelease];
	
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
-(void) _authenticationDidFail:(FRXAuthRequest*) aRequest{
	NSLog(@"Hard Fail => HTTP Error:%d", [aRequest responseStatusCode]);
	
	FRXAuthRequest	*parentRequest;
	
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

@end
