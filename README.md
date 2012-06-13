SimpleWebToken
==============

The minimum library to handle SimpleWebTokens

## Usage

```
Install-Package Auth10.SimpleWebToken
```

And the simplest validation is

```cs
var validator = new SimpleWebTokenValidator 
{
	SharedKeyBase64 = "...base64key..."	
}
var swt = validator.ValidateToken(token); // this will throw an exception if the token is invalid
// if valid you can access claims with: swt.Claims
```

If you want to validate audience and issuer. Setting the properties will instruct the library to validate them.

```cs
var validator = new SimpleWebTokenValidator 
{
	SharedKeyBase64 = "...base64key...",
	Issuer = "issuer-identifier"  // e.g.: https://auth10.accesscontrol.windows.net	
}
validator.AllowedAudiences.Add(new Uri("http://server/myapi"));
var swt = validator.ValidateToken(token); // this will throw an exception if the token is invalid
```

