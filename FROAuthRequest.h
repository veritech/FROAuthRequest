//
//  FROAuthRequest.h
//  kroonjuwelen
//
//  Created by Jonathan Dalrymple on 12/04/2010.
//  Copyright 2010 Float:Right. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASIFormDataRequest.h"
//#import "OAHMAC_SHA1SignatureProvider.h"
//#import "OAMutableURLRequest.h"

#import "OAuthConsumer.h"

#define DEBUG 0

@class OAHMAC_SHA1SignatureProvider;
@class OAToken;

@interface FROAuthRequest : ASIFormDataRequest {
	
	@private
	OAToken		*_token;
	OAConsumer	*_consumer;
	
	id<OASignatureProviding> _signatureProvider;
	
	NSString	*_timestamp, *_nonce, *_realm;
	
	NSDictionary	*_userInfo;

}

@property (nonatomic, retain) OAToken		*token;
@property (nonatomic, retain) OAConsumer	*consumer;

@property (nonatomic, retain) NSDictionary	*_userInfo;

@property (nonatomic, retain) id			signatureProvider;

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

+(OAToken*) _requestTokenFromProvider:(NSURL*) requestURL 
					 withConsumer:(OAConsumer*) pConsumer 
						forObject:(id) pDelegate;

+(OAToken*) _didRequestToken:(FROAuthRequest*) pRequest 
				   forObject:pDelegate;

+(OAToken*) _accessTokenWithRequestToken:(OAToken*) pToken 
							fromProvider:(NSURL*) accessURL 
							 forConsumer:(OAConsumer*) pConsumer
							   forObject:(id) pDelegate;

@end
