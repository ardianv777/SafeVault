using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SafeVault.Data;
using SafeVault.Data.Repositories;
using SafeVault.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure Database Context (In-Memory for agile security testing or SQLite)
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseInMemoryDatabase("SafeVaultDb"));

// 2. Dependency Injection for Security Services & Repositories
builder.Services.AddScoped<IVaultRepository, VaultRepository>();
builder.Services.AddScoped<ITokenService, TokenService>();

// 3. Configure JWT Authentication with Strict Validation Parameters
// Generated with Microsoft Copilot following Course 8 Security Standards
var jwtSecretKey = builder.Configuration["Jwt:Key"] ?? "SafeVaultSuperSecretKey2026!MustBeAtLeast32BytesLong!";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Set to true in production
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVaultAPI",
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultClients",
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ClockSkew = TimeSpan.Zero // Enforce immediate expiration without default 5-minute tolerance
    };
});

// 4. Configure Role-Based Access Control (RBAC) Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
    options.AddPolicy("RequireAuditorRole", policy => policy.RequireRole("Admin", "Auditor"));
    options.AddPolicy("RequireUserRole", policy => policy.RequireRole("Admin", "User"));
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 5. Configure Swagger with JWT Bearer Authorization support
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SafeVault Security API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// 6. Security Headers Middleware (Defense-in-depth against Clickjacking, MIME-sniffing, XSS)
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");
    await next();
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Enforce Authentication and Authorization pipeline in correct order
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
