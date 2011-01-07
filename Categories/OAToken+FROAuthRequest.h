//
//  OAToken+FROAuthRequest.h
//  SOTM
//
//  Created by Jonathan Dalrymple on 07/01/2011.
//  Copyright 2011 Float:Right. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface OAToken(FROAuthRequest)

+(OAToken*) tokenWithURLQuery:(NSURL*) aURL;

@end
