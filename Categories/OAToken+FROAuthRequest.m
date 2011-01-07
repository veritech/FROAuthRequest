//
//  OAToken+FROAuthRequest.m
//  SOTM
//
//  Created by Jonathan Dalrymple on 07/01/2011.
//  Copyright 2011 Float:Right. All rights reserved.
//

#import "OAToken+FROAuthRequest.h"


@implementation OAToken(FROAuthRequest)

+(OAToken*) tokenWithURLQuery:(NSURL*) aURL{

	NSString	*query;
	
	query = [aURL parameterString];
	
	return [[[self alloc] initWithHTTPResponseBody:query] autorelease];
}

@end
