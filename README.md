**FROAuthRequest**
===================

What is it?
----------------
FROAuthRequest enables you to make OAuth requests while enjoying all the benefits of the fantastic ASIHTTPRequest library

This code borrows heavily from jdg's [OAuthConsumer](https://github.com/jdg/oauthconsumer), reusing his OAToken, OASignature and associated categories.

---

What can it do?
---------------
Connect to OAuth (1.*) webservices. The most famous of these is Twitter's API. If your looking for OAuth2 support, see my FROAuth2Request classes.

***Features***

* OAuth 1.*
* XAuth (Twitter's simplified version)
* single method Token requests
* single method authentication token exchanges

---

Dependencies
------------
ASIHTTPRequest 1.8
Security.framework
iOS 4.0+ (for block support, which is used internally)

---

How do i use it?
----------------

For the most part you use it just like you would use a normal ASIHTTPRequest.
The chief difference being that you use a modified constructor see below...

<code>
	
	FROAuthRequest *request;
	
	request = [FROAuthRequest requestWithURL:aURL
							consumer: aOAConsumer
							token: aOAToken
							realm: aRealm
							signatureProvider: aOASignatureProvider
		
	];
	
	[request startAsynchronous];
</code>

After that it behaves just like any normal ASIHTTPRequest. The FROAuthRequest is a subclass of the ASIFormDataRequest,
so it supports all HTTP verbs (GET,POST,PUT,DELETE) along with form data.

So i hear what your thinking, thats nice and all, but how to actually get a request token?

***Getting a "Request Token"***

Well i've tried to give you as much freedom as you like. To fetch a request token it's as simple as

<code>
	
	[FROAuthRequest requestTokenFromProvider:aTokenRequestURL
								withConsumer:aConsumer
								OAuthCallback:nil
									delegate:self
	];
	
</code>

Yep, thats it.

This method will execute it's self when ready. Your delegate, a *FROAuthenticationDelegate* needs to respond to ...

<code>

	-(void) OAuthRequest:(FROAuthRequest*) aRequest didReceiveRequestToken:(OAToken*) aToken{
		//Open a browser of some sort to have the user authenticate you
	}

</code>

There is a failure method too, but we're all rockstars so our code never fails ... am i right ...

With the token that you've been given you can direct your user via a browser, internal or external using the custom callback ;) to the webservices authorize endpoint.

***Exchanging your "Request Token" for a "Access Token"***

I've added a category to the OAToken so you can convert the URL into a token without breaking a sweat using the *tokenWithURLQuery:* method.
Once you've got that token you can simply call the method below to do the whole token swap for you.

<code>
	
	[FROAuthRequest requestAuthorizedTokenFromProvider:aAccessTokenURL
	 										withConsumer:aConsumer
	 										requestToken:aRequestToken
	 											delegate:self
	];
	
</code>

Once this method has fetched your shiny new access token, it will automatically create your token for you and call this method

<code>
	
	-(void) OAuthRequest:(FROAuthRequest*) aRequest didReceiveAuthorizedToken:(OAToken*) aToken{
		//Do as you wish with your shiny new authorized token
	}	
	
</code>

And thats all folks!

***So what about XAuth***

Well thats a work in progress at the moment. It 'should' work but is a bit messy. If your interesting in finding out some more checkout the *FRXAuthRequest* subclass.

---

Credits
------------
***Authors***

Jonathan Dalrymple	([Veritech][jonathanGithub]) 	[Online][jonathanWeb],[Twitter][jonathanTwitter],[Email][jonathanEmail]

***Sponsors***

Joe Carney											[Online][joesWeb],[Twitter][joesTwitter]

***Attribution***

Jonathan George 	([jdg][jonathanGGithub])

<!-- Links -->
[joesWeb]: http://northoftheweb.com
[joesTwitter]: http://twitter.com/joe_carney

[jonathanWeb]: http://float-right.co.uk
[jonathanTwitter]: http://twitter.com/veritech
[jonathanGithub]: http://github.com/veritech
[jonathanEmail]: mailto:jonathan@float-right.co.uk

[jonathanGGithub]: http://github.com/jdg




