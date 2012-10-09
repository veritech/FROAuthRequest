//
//  FROAuthRequest.h
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

#import <Foundation/Foundation.h>
#import "ASIFormDataRequest.h"

#import "OAConsumer.h"
#import "OAToken.h"
#import "OAHMAC_SHA1SignatureProvider.h"
#import "NSString+URLEncoding.h"
#import "NSURL+Base.h"
#import "OAToken+FROAuthRequest.h"

#define DEBUG 1

@protocol FROAuthenticationDelegate;

@interface FROAuthRequest : ASIFormDataRequest {
	
	@private
	OAToken		*_token;
	OAConsumer	*_consumer;
	
	id<OASignatureProviding> _signatureProvider;
	
	NSString	*_timestamp, *_nonce, *_realm;

}

@property (nonatomic, retain) OAToken		*token;
@property (nonatomic, retain) OAConsumer	*consumer;
@property (nonatomic, retain) id			signatureProvider;

/**
 *	Fetch a request token
 */
+(void) requestTokenFromProvider:(NSURL*) aURL 
					withConsumer:(OAConsumer*) aConsumer
				   OAuthCallback:(NSString*) aCallback
						delegate:(id<FROAuthenticationDelegate>) aDelegate;

/**
 *	Fetch a authorization request
 */
+(void) requestAuthorizedTokenFromProvider:(NSURL*) aURL 
							  withConsumer:(OAConsumer*) aConsumer 
							  requestToken:(OAToken*) aToken 
								  delegate:(id<FROAuthenticationDelegate>) aDelegate;


//Usual commands
+(id) requestWithURL: (NSURL *)newURL  
			consumer: (OAConsumer*) consumer
			   token: (OAToken*) token
			   realm: (NSString*) realm
   signatureProvider: (id<OASignatureProviding>) provider;

-(id) initWithURL: (NSURL *)newURL  
			consumer: (OAConsumer*) consumer
			   token: (OAToken*) token
			   realm: (NSString*) realm
   signatureProvider: (id<OASignatureProviding>) provider;

/*
+(OAToken*) _accessTokenWithRequestToken:(OAToken*) pToken 
							fromProvider:(NSURL*) accessURL 
							 forConsumer:(OAConsumer*) pConsumer
							   forObject:(id) pDelegate;
*/

- (NSString *)signatureBaseString;
@end

@protocol FROAuthenticationDelegate

@optional
-(void) OAuthRequest:(FROAuthRequest*) aRequest didReceiveRequestToken:(OAToken*) aToken;
-(void) OAuthRequest:(FROAuthRequest*) aRequest didReceiveAuthorizedToken:(OAToken*) aToken;
-(void) OAuthRequest:(FROAuthRequest*) aRequest didFailWithError:(NSError*) anError;

@end