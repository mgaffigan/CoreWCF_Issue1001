using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var baseUrl = "http://localhost:12345";
// server
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(baseUrl);
builder.Services.AddControllers();
builder.Services.AddAuthentication()
    .AddScheme<AuthenticationSchemeOptions, FakeJwtHandler>(FakeJwtHandler.AuthenticationScheme, configureOptions: null);
builder.Services.AddAuthorization(opts =>
{
    opts.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAssertion(hc =>
    {
        Console.WriteLine("Fallback");
        return true;
    }).Build();
    opts.AddPolicy("Anonymous", policy => policy.RequireAssertion(hc =>
    {
        Console.WriteLine("Anonymous"); 
        return true;
    }));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

var promise = app.RunAsync();

// client
var hc = new HttpClient();
var resp = await hc.GetAsync(baseUrl + "/api/ok");
resp.EnsureSuccessStatusCode();

// teardown
await app.StopAsync();
await promise;

// Implementation
[ApiController]
[Route("api")]
public class ExampleWebApiController : ControllerBase
{
    [HttpGet("ok"), Authorize("Anonymous")]
    public IActionResult GetOk() => Ok();
}

class FakeJwtHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string AuthenticationScheme = "FakeJwtBearer";

    public FakeJwtHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity(new[] { new Claim("sub", Guid.NewGuid().ToString()) }, AuthenticationScheme);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), AuthenticationScheme);
        return Task.FromResult(AuthenticateResult.Success(ticket));
        //return Task.FromResult(AuthenticateResult.NoResult());
    }
}