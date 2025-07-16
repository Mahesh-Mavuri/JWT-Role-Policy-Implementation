using JWTSelfAuth.AuthorizationHelpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(
    c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 1safsfsdfdfd\"",
});

    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "JWT Authentication",
        Version = "v1"
    });

    // Apply the security requirement to all endpoints
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
        {
            {
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Reference = new Microsoft.OpenApi.Models.OpenApiReference
                    {
                        Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                new string[] {}
            }
        });

});

// Configure JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme; // Added for completeness
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
// Configure Policy-Based Authorization
builder.Services.AddAuthorization(options =>
{
    // --- Policy 1: Requires a specific role (example of policy encapsulating a role requirement) ---
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin")); // Same as [Authorize(Roles = "Admin")] but as a policy

    // --- Policy 2: Requires a specific claim value ---
    // First, make sure your JWT generation adds a custom claim, e.g., "permission"
    // In AuthController.cs -> GenerateJwtToken, you might add:
    // claims.Add(new Claim("permission", "can_view_dashboard"));
    // claims.Add(new Claim("permission", "can_edit_products")); // User can have multiple "permission" claims

    options.AddPolicy("CanViewDashboard", policy =>
        policy.RequireClaim("permission", "can_view_dashboard"));

    // --- Policy 3: Requires multiple claim values (AND logic for values within the same claim type) ---
    options.AddPolicy("CanManageProducts", policy =>
        policy.RequireClaim("permission", "can_create_product", "can_edit_product", "can_delete_product"));
    // This means the user MUST have ALL three 'permission' claims.
    // If a user only has "can_create_product", this policy would fail.

    // --- Policy 4: Requires a minimum age (example of a custom requirement) ---
    // This involves creating a custom IAuthorizationRequirement and an IAuthorizationHandler.
    // (See next section for detailed implementation of this type of policy)
    options.AddPolicy("MinimumAge18", policy =>
       policy.Requirements.Add(new MinimumAgeRequirement(18)));

    // --- Policy 5: Combining Role and Claim requirements (AND logic) ---
    options.AddPolicy("AdminAndCanViewLogs", policy =>
        policy.RequireRole("Admin")
              .RequireClaim("permission", "can_view_logs")); // Must be Admin AND have 'can_view_logs' permission
});

builder.Services.AddAuthorization(); // Add authorization services

// Register your custom authorization handler
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); // IMPORTANT: This must be before UseAuthorization
app.UseAuthorization();   // IMPORTANT: This must be after UseAuthentication

app.MapControllers();

app.Run();
