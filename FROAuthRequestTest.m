//
//  FROAuthRequestTest.m
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

#import "GHUnit.h"
#import "FROAuthRequest.h"

@interface FROAuthRequestTest : GHAsyncTestCase{
	id _subject;
}

@end

@implementation FROAuthRequestTest

-(void) setUp{
	_subject = [FROAuthRequest requestWithURL: [NSURL URLWithString:@"http://term.ie/oauth/example/echo_api.php"] 
									 consumer: [[[OAConsumer alloc] initWithKey: @"key" secret: @"secret"] autorelease] 
										token: nil 
										realm: nil 
							signatureProvider: nil
				 ];
		
	[_subject setDelegate: self];

}

-(void) tearDown{
	//[_subject release];
}

-(void) testInstance{
	
	GHAssertNotNil(_subject, @"Not Nil");
	
	GHAssertTrue([_subject isKindOfClass:[FROAuthRequest class]],@"Kind of class");
	
	GHAssertNotNil([_subject consumer],@"Is there a consumer");
	
	//GHAssertNotNil([_subject signatureProvider],@"Is a signature provider");
	
	//GHAssertNotNil([_subject requestToken],@"Request Token");
	
	
}

-(void) testFactoryInit{
	
	
	GHAssertNotNil( _subject, @"Test Nil");
	
	GHAssertNotNil( [_subject consumer], @"Test consumer");
	
	GHAssertNotNil( [_subject url], @"Test URL");

	GHAssertNotNil( [_subject token], @"Token is nil");
	
	GHAssertNotNil( [_subject signatureProvider], @"SignatureProvider is nil");
	
}

-(void) testTokenProperty{
	
	GHAssertNotNil([_subject token],@"Not nil");
	
	GHAssertTrue( [[_subject token] isKindOfClass:[OAToken class]], @"Is OAToken");
}


-(void) testPrivateGenerateNonce{
	
	GHAssertNotNil([_subject nonce],@"Nonce Not Nil");
	
	GHAssertEquals([_subject nonce],[_subject nonce],@"Values are equal");
}

-(void) testPrivateGenerateSignatureBase{
	
	
	NSString *result;
	
	[_subject setURL: [NSURL URLWithString:@"http://term.ie/oauth/example/request_token.php"]];
	
	[_subject setRequestMethod:@"GET"];
	
	[_subject setSignatureProvider:[[OAHMAC_SHA1SignatureProvider alloc] init]];
	
	
	result = [_subject signatureBaseString];
	
	GHAssertNotNil( result,@"BaseString Not Nil");
	
	GHAssertTrue([result isKindOfClass:[NSString class]],@"BaseString is a String");
}

-(void) testPrivateGenerateTimeStamp{
	
	//GHAssertNotNil( [_subject timestamp] , @"Time Stamp not nil");
	
	//GHAssertTrue( [[_subject timestamp] isKindOfClass:[NSString class]],@"Is string");
	
	GHAssertEquals( [_subject timestamp], [_subject timestamp], @"Timestamps are equal");

}

-(void) testSignatureOne{

	NSDictionary *params = [NSDictionary dictionaryWithObjectsAndKeys:
							@"dpf43f3p2l4k3l03",
							@"oauth_consumer_key",
							@"nnch734d00sl2jdk",
							@"oauth_token",
							@"HMAC-SHA1",
							@"oauth_signature_method",
							@"1191242096",
							@"oauth_timestamp",
							@"kllo9940pd9333jh",
							@"oauth_nonce",
							@"1.0",
							@"oauth_version",
							@"vacation.jpg",
							@"file",							
							@"original",
							@"size",
							nil
							];
	
	NSString* baseText = [_subject signatureBaseStringForURL:[NSURL URLWithString:@"http://photos.example.net/photos"] 
												  withMethod:@"GET" 
												  withParams: params
						  ];
	
	NSString* sampleBase = @"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";

	//NSLog(@"===========\r\n BASE TEXT \r\n===========\r\n%@\r\n===========", baseText );
	
	GHAssertTrue( [baseText isEqualToString:sampleBase],@"BaseStrings Match" );

	OAHMAC_SHA1SignatureProvider *provider;
	NSString *genSignature;
	
	provider = [[OAHMAC_SHA1SignatureProvider alloc] init];
	
	genSignature = [provider signClearText:baseText withSecret: @"kd94hf93k423kf44&pfkkdhi9sl3r4s00"];
	
	//Test signature
	GHAssertTrue( [@"tR3+Ty81lMeYAr/Fid0kMTYa/WM=" isEqualToString:genSignature],@"Signature");
	
	[provider release];
}

-(void) testSignatureTwo{
	
	NSDictionary	*params;
	NSString		*sampleBase, *baseText;
	
	params = [NSDictionary dictionaryWithObjectsAndKeys:
							@"key",
							@"oauth_consumer_key",
							@"",
							@"oauth_token",
							@"HMAC-SHA1",
							@"oauth_signature_method",
							@"1271249191",
							@"oauth_timestamp",
							@"578FDDB6-869F-4E48-AE60-D90A3372BF06",
							@"oauth_nonce",
							@"1.0",
							@"oauth_version",
							nil
							];
	
	sampleBase = @"GET&http%3A%2F%2Fterm.ie%2Foauth%2Fexample%2Frequest_token.php&oauth_consumer_key%3Dkey%26oauth_nonce%3D578FDDB6-869F-4E48-AE60-D90A3372BF06%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1271249191%26oauth_version%3D1.0";
	
	
	baseText = [_subject signatureBaseStringForURL:[NSURL URLWithString:@"http://term.ie/oauth/example/request_token.php"] 
												  withMethod:@"GET" 
												  withParams: params
						  ];
	
	//NSLog(@"\r\n======ACTUAL======\r\n%@\r\n===== SAMPLE ======\r\n%@\r\n=============", baseText, sampleBase );

	GHAssertTrue( [baseText isEqualToString:sampleBase],@"BaseStrings Match" );

}

-(void) testXAuthSignature{
	
	NSDictionary	*params;
	NSString		*sampleBase, *baseText;
	
	params = [NSDictionary dictionaryWithObjectsAndKeys:
			  @"ri8JxYK2ZdwSV5xIUfNNvQ",//@"ri8JxYK2ddwSV5xIUfNNvQ",
			  @"oauth_consumer_key",
			  @"HMAC-SHA1",
			  @"oauth_signature_method",
			  @"1267817662",
			  @"oauth_timestamp",
			  @"qfQ4ux5qRH9GaH8tVwDCwInLy6z8snR6wiq8lKcD6s",
			  @"oauth_nonce",
			  @"1.0",
			  @"oauth_version",
			  @"xyz12242134",
			  @"x_auth_password",
			  @"episod",
			  @"x_auth_username",
			  @"client_auth",
			  @"x_auth_mode",
			  nil
			  ];
	
	sampleBase = @"POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3Dri8JxYK2ZdwSV5xIUfNNvQ%26oauth_nonce%3DqfQ4ux5qRH9GaH8tVwDCwInLy6z8snR6wiq8lKcD6s%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1267817662%26oauth_version%3D1.0%26x_auth_mode%3Dclient_auth%26x_auth_password%3Dxyz12242134%26x_auth_username%3Depisod";
	
	
	baseText = [_subject signatureBaseStringForURL:[NSURL URLWithString:@"https://api.twitter.com/oauth/access_token"] 
										withMethod:@"POST" 
										withParams: params
				];
	
	//NSLog(@"\r\n======ACTUAL======\r\n%@\r\n===== SAMPLE ======\r\n%@\r\n=============", baseText, sampleBase );
	
	GHAssertTrue( [baseText isEqualToString:sampleBase],@"BaseStrings Match" );

}

//========================
-(void) testXAuth{
	
	OAToken* token;
	OAConsumer* consumer;
	
	consumer = [[OAConsumer alloc] initWithKey: @"MFJ8Fi7BM60EJzbeI9WA"
										secret: @"KhseBD7BzunTv9uXKiB9QgBUQJlq69w0F1UwxOolig"
				];
	
	
	token = [FROAuthRequest _accessTokenFromProvider: [NSURL URLWithString: @"https://twitter.com/oauth/access_token"] 
										WithUsername: @"veritech" 
											password: @"robotech" 
										 andConsumer: consumer
			 ];
	

	
	GHAssertNotNil( token, @"Token not nil");
	
	GHAssertNotNil([token key], @"Token has a key");
	
	[consumer release];
	[token release];
}


-(void) testAuthenticatedRequest{

	
	//Create a fake token
	OAToken *token = [[OAToken alloc] initWithKey:@"accesskey" secret:@"accesssecret"];
	
	[_subject setToken:token];
	
	[token release];

	[_subject startSynchronous];
	
	
	GHAssertEquals( [_subject responseStatusCode], 200, @"Returned 200");
}

-(void) testAuthenticatedRequestWithParams{
	
	NSString *urlStr;
	//Get the url
	urlStr = [[_subject url] absoluteString];
	
	urlStr = [urlStr stringByAppendingString:@"?foo=bar"];
	
	[_subject setURL:[NSURL URLWithString:urlStr]];
	
	//Create a fake token
	OAToken *token = [[OAToken alloc] initWithKey:@"accesskey" secret:@"accesssecret"];
	
	[_subject setToken:token];
	
	[token release];
	
	[_subject startSynchronous];
	
	GHAssertEquals( [_subject responseStatusCode], 200, @"Returned 200");

}

-(void) testAuthenticatedPostRequestWithParams{
	
	//Create a fake token
	OAToken *token = [[OAToken alloc] initWithKey:@"accesskey" secret:@"accesssecret"];
	
	[_subject setToken:token];
	
	[token release];
	
	[_subject setRequestMethod:@"POST"];
	
	[_subject setPostValue:@"foo" forKey:@"bar"];
	
	[_subject setPostValue:@"bar" forKey:@"foo"];
	
	[_subject startSynchronous];
	
	GHAssertEquals( [_subject responseStatusCode], 200, @"Returned 200");
	
}

//ASYNC TESTS
/*
 -(void) testPrivateRequestToken{
 [self prepare:@selector(testPrivateRequestToken)];
 
 [_subject setDidFinishSelector:@selector(requestTokenDidFinish:)];
 [_subject setDidFailSelector:@selector(requestDidFail:)];
 
 [_subject _requestToken];
 
 
 [self waitForStatus:kGHUnitWaitStatusSuccess timeout:5.0f];
 
 }
 
 -(void) requestTokenDidFinish:(FROAuthRequest*) request{
 
 @try{
 //Tests
 GHAssertTrue( [request isKindOfClass:[FROAuthRequest class]], @"Test class type");
 
 GHAssertNotNil( [request token],@"Request Token");
 
 GHAssertTrue( [[[request token] key] isEqualToString:@"accesskey"], @"AccessToken Key is valid");
 
 GHAssertTrue( [[[request token] secret] isEqualToString:@"accesssecret"], @"AccessToken Secret is valid");
 }
 @catch (NSException *ex) {
 [self handleException: ex];
 }
 
 [self notify:kGHUnitWaitStatusSuccess forSelector:@selector(testPrivateRequestToken)];
 
 }
 
 -(void) requestTokenDidFail:(FROAuthRequest*) request{
 
 [self notify:kGHUnitWaitStatusFailure forSelector: @selector(testPrivateRequestToken)];
 }
 */

@end
