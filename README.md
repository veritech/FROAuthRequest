**FROAuthRequest**
====================================================================

What is it?
----------------
FROAuthRequest enables you to make OAuth requests while enjoying all the benefits of the fantastic ASIHTTPRequest library

This code borrows heavily from jdg's OAuthConsumer (https://github.com/jdg/oauthconsumer), reusing his OAToken, OASignatures and associated categories.

It's also completely freestanding and doesn't come with a crap load of dependencies.

What can it do?
---------------
Connect to OAuth (1.*) webservices. The most famous of these is Twitter's API. If your looking for OAuth2 support, see my FROAuth2Request classes.

***Features***

* XAuth (Twitter's simplified version)
* OAuth 1.*



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


Credits
------------
***Authors***

Jonathan Dalrymple(veritech) 	jonathan@float-right.co.uk

***Sponsors***

Joe Carney						http://northoftheweb.com

***Attribution***

Jonathan George(jdg)			jonathan@jdg.net








