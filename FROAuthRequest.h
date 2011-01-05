//
//  FROAuthRequest.h
//
//  Created by Jonathan Dalrymple on 12/04/2010.
//  Copyright 2010 Float:Right. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASIFormDataRequest.h"

#import "OAuthConsumer.h"

#define DEBUG 1

@interface FROAuthRequest : ASIFormDataRequest {
	
	@private
	OAToken		*_token;
	OAConsumer	*_consumer;
	
	id<OASignatureProviding> _signatureProvider;
	
	NSString	*_timestamp, *_nonce, *_realm, *_requestTokenURL;

}

@property (nonatomic, retain) OAToken		*token;
@property (nonatomic, retain) OAConsumer	*consumer;
@property (nonatomic, retain) id			signatureProvider;

@property (nonatomic, retain) NSString		*requestTokenURL;

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

+(OAToken*) _accessTokenWithRequestToken:(OAToken*) pToken 
							fromProvider:(NSURL*) accessURL 
							 forConsumer:(OAConsumer*) pConsumer
							   forObject:(id) pDelegate;

@end
