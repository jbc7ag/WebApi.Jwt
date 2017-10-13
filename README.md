# WebApi.Jwt
Authentication for ASP.NET Web Api using simple JWT

Now, lots of things changed in security, esp JWT is getting popular. In here, I will try to explain how to use JWT in the simplest and basic way that I can, so we won't get lost from jungle of OWIN, Oauth2, ASP.NET Identity... :).

If you don't know JWT token, you need to take a look a little bit at:

https://tools.ietf.org/html/rfc7519

Basically, a JWT token look like:

    <base64-encoded header>.<base64-encoded claims>.<base64-encoded signature>

Example:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImN1b25nIiwibmJmIjoxNDc3NTY1NzI0LCJleHAiOjE0Nzc1NjY5MjQsImlhdCI6MTQ3NzU2NTcyNH0.6MzD1VwA5AcOcajkFyKhLYybr3h13iZjDyHm9zysDFQ
JWT token has three sections:

Header: JSON format which is encoded as a base64
Claims: JSON format which is encoded as a base64.
Signature: Created and signed based on Header and Claims which is encoded as a base64.
If you use the website jwt.io with token above, you can decode and see the token like below:

enter image description here

Technically, JWT uses signature which is signed from headers and claims with security algorithm specified in the headers (example: HMACSHA256). Therefore, JWT is required to be transferred over HTTPs if you store any sensitive information in claims.

Now, in order to use JWT authentication, you don't really need an OWIN middleware if you have legacy Web Api system. The simple concept is how to provide JWT token and how to validate token when the request comes. That's it.

Back to the demo, to keep JWT token lightweight, I only store username and expiration time in JWT. But this way, you have to re-build new local identity (principal) to add more information like: roles.. if you want to do role authorization. But, if you want to add more information into JWT, it's up to you, very flexible.

Instead of using OWIN middleware, you can simply provide JWT token endpoint by using action from controller:

    public class TokenController : ApiController {
    // This is naive endpoint for demo, it should use Basic authentication to provide token or POST request
    [AllowAnonymous]
    public string Get(string username, string password)
    {
        if (CheckUser(username, password))
        {
            return JwtManager.GenerateToken(username);
        }

        throw new HttpResponseException(HttpStatusCode.Unauthorized);
    }

     public bool CheckUser(string username, string password)
       {
        // should check in the database
        return true;
      }
    }

This is naive action, in production you should use POST request or Basic Authentication endpoint to provide JWT token.

How to generate the token based on username?

You can use the NuGet package called System.IdentityModel.Tokens.Jwt from MS to generate the token, or even another package if you like. In the demo, I use HMACSHA256 with SymmetricKey:

    /// <summary>
    /// Use the below code to generate symmetric Secret Key
    ///     var hmac = new HMACSHA256();
    ///     var key = Convert.ToBase64String(hmac.Key);
    /// </summary>
    private const string Secret = "db3OIsj+BXE9NZDy0t8W3TcNekrF+2d/1sFnWG4HnV8TZY30iTOdtVWJG8abWvB1GlOgJuQZdcF2Luqm/hccMw==";

    public static string GenerateToken(string username, int expireMinutes = 20)
    {
        var symmetricKey = Convert.FromBase64String(Secret);
        var tokenHandler = new JwtSecurityTokenHandler();

        var now = DateTime.UtcNow;
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, username)
                    }),

            Expires = now.AddMinutes(Convert.ToInt32(expireMinutes)),

            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var stoken = tokenHandler.CreateToken(tokenDescriptor);
        var token = tokenHandler.WriteToken(stoken);

        return token;
    }


The endpoint to provide the JWT token is done, now, how to validate the JWT when the request comes, in the demo I have built  JwtAuthenticationAttribute which inherits from IAuthenticationFilter, more detail about authentication filter in here.

With this attribute, you can authenticate any action, you just put this attribute on that action.

    public class ValueController : ApiController
    {
     [JwtAuthentication]
     public string Get()
      {
        return "value";
      }
    }

You also can use OWIN middleware or DelegateHander if you want to validate all incoming request for your WebApi (not specific on Controller or action)

Below is the core method from authentication filter:

    private static bool ValidateToken(string token, out string username)
    {
        username = null;

        var simplePrinciple = JwtManager.GetPrincipal(token);
        var identity = simplePrinciple.Identity as ClaimsIdentity;

        if (identity == null)
            return false;

        if (!identity.IsAuthenticated)
            return false;

        var usernameClaim = identity.FindFirst(ClaimTypes.Name);
        username = usernameClaim?.Value;

        if (string.IsNullOrEmpty(username))
            return false;

        // More validate to check whether username exists in system

        return true;
    }

    protected Task<IPrincipal> AuthenticateJwtToken(string token)
    {
        string username;

        if (ValidateToken(token, out username))
        {
            // based on username to get more information from database in order to build local identity
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, username)
                // Add more claims if needed: Roles, ...
            };

            var identity = new ClaimsIdentity(claims, "Jwt");
            IPrincipal user = new ClaimsPrincipal(identity);

            return Task.FromResult(user);
        }

        return Task.FromResult<IPrincipal>(null);
    }
The workflow is, using JWT library (NuGet package above) to validate JWT token and then return back ClaimsPrincipal. You can perform more validation like check whether user exists on your system and add other custom validations if you want. The code to validate JWT token and get principal back:

    public static ClaimsPrincipal GetPrincipal(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            if (jwtToken == null)
                return null;

            var symmetricKey = Convert.FromBase64String(Secret);

            var validationParameters = new TokenValidationParameters()
            {
               RequireExpirationTime = true,
               ValidateIssuer = false,
               ValidateAudience = false,
               IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
            };

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out securityToken);

            return principal;
        }

        catch (Exception)
        {
            //should write log
            return null;
        }
    }
If the JWT token is validated and principal is return, you should build new local identity and put more information into it to check role authorization.

Remember to add config.Filters.Add(new AuthorizeAttribute()); (default authorization) at global scope in order to prevent any anonymous request to your resources.

You can use Postman to test the demo:

Request token (naive as I mentioned above, just for demo):

    GET http://localhost:{port}/api/token?username=cuong&password=1
Put JWT token in the header for authorized request, example:

    GET http://localhost:{port}/api/value

Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImN1b25nIiwib
