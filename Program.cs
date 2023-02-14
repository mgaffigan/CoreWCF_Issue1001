using CoreWCF;
using CoreWCF.Channels;
using CoreWCF.Configuration;
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
builder.Services.AddServiceModelServices();
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

app.UseServiceModel(c =>
{
    c.AddService<WcfService>()
        .AddServiceEndpoint<WcfService, IWcfService>(new BasicHttpBinding
        {
            Security = new BasicHttpSecurity
            {
                Mode = BasicHttpSecurityMode.TransportCredentialOnly,
                Transport = new HttpTransportSecurity
                {
                    ClientCredentialType = HttpClientCredentialType.InheritedFromHost
                }
            }
        }, "/IWcfService");
});

var promise = app.RunAsync();

// client
var hc = new HttpClient();
var postRequest = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/IWcfService");
postRequest.Content = new StringContent(
    @"<Envelope xmlns=""http://schemas.xmlsoap.org/soap/envelope/""><Body><Hello xmlns=""urn:example""/></Body></Envelope>",
    new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml")
);
postRequest.Headers.Add("SOAPAction", "urn:example/IWcfService/Hello");
var resp = await hc.SendAsync(postRequest);
resp.EnsureSuccessStatusCode();

// teardown
await app.StopAsync();
await promise;

// Implementation
[ServiceContract(Namespace = "urn:example")]
public interface IWcfService
{
    [OperationContract]
    void Hello();
}

public class WcfService : IWcfService
{
    [Authorize("Anonymous")]
    public void Hello() { }
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