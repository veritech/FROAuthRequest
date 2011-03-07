//
//  OAToken+FROAuthRequest.m
//
//  Created by Jonathan Dalrymple on 07/01/2011.
//  Copyright 2011 Float:Right. All rights reserved.
//

#import "OAToken+FROAuthRequest.h"


@implementation OAToken(FROAuthRequest)

+(OAToken*) tokenWithURLQuery:(NSURL*) aURL{

	NSString	*query;
	
	query = [aURL query];
	
	NSLog(@"Query str %@",query);
	
	return [[[self alloc] initWithHTTPResponseBody:query] autorelease];
}

//Establish if we have a default token for a given service
+(BOOL) hasDefaultTokenForService:(NSString*) serviceName{
	
	OAToken *token;
	
	token = [[[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:serviceName 
																   prefix:@"default"
			 ] autorelease];
	
	if( token != nil ){
		return YES;
	}
	else{
		return NO;
	}
}

//Save a default token
-(void) saveAsDefaultTokenForService:(NSString*) serviceName{
	[self storeInUserDefaultsWithServiceProviderName:serviceName 
											  prefix:@"default"
	 ];
}

//Load a default token
+(OAToken*) tokenDefaultForService:(NSString*) serviceName{
	return [[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:serviceName 
																  prefix:@"default"
			];
}

//Clear a default token
+(void) removeDefaultTokenForService:(NSString*) serviceName{
	[OAToken removeFromUserDefaultsWithServiceProviderName:serviceName
													prefix:@"default"
	 ];
}

@end
