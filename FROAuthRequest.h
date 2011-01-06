//
//  FROAuthRequest.h
//
//  Created by Jonathan Dalrymple on 12/04/2010.
//  Copyright 2010 Float:Right. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASIFormDataRequest.h"

#import "OAConsumer.h"
#import "OAToken.h"
#import "OAHMAC_SHA1SignatureProvider.h"
#import "NSString+URLEncoding.h"
#import "NSURL+Base.h"

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

//Authentication
+(void) requestTokenFromProvider:(NSURL*) aURL 
					withConsumer:(OAConsumer*) aConsumer 
					withDelegate:(id<FROAuthenticationDelegate>) aDelegate;

+(OAToken*) authenticatedTokenWithHTTPResponse:(NSString*)aResponse;

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

-(void) OAuthRequestDidReceiveRequestToken:(FROAuthRequest*) aRequest;
//-(void) OAuthRequest:(FROAuthRequest*) aRequest didReceiveAuthenticatedToken:(OAToken*) aToken;
-(void) OAuthRequestDidFail:(FROAuthRequest*) aRequest;

@end