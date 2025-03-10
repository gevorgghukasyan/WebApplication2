using JWTAuthentication.API.Entities;
using JWTAuthentication.API.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.API
{
	public class Response
	{
		public string? Status { get; set; }
		public string? Message { get; set; }
	}
}

namespace JWTAuthentication.API.Identity
{
	/// <summary>
	/// This attribute checks that the token contains a claim with the specified name and value.
	/// You can use it to protect endpoints that should be available only when a particular product or permission is allowed.
	/// </summary>
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
	public class RequiresClaimAttribute : Attribute, IAuthorizationFilter
	{
		private readonly string _claimName;
		private readonly string _claimValue;

		public RequiresClaimAttribute(string claimName, string claimValue)
		{
			_claimName = claimName;
			_claimValue = claimValue;
		}

		public void OnAuthorization(AuthorizationFilterContext context)
		{
			if (!context.HttpContext.User.HasClaim(_claimName, _claimValue))
			{
				context.Result = new ForbidResult();
			}
		}
	}

	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
	public class RequiresProductAttribute : Attribute, IAuthorizationFilter
	{
		private readonly Product _requiredProduct;

		public RequiresProductAttribute(Product product)
		{
			_requiredProduct = product;
		}

		public void OnAuthorization(AuthorizationFilterContext context)
		{
			if (!context.HttpContext.User.HasClaim("allowed_product", _requiredProduct.ToString()))
			{
				context.Result = new ForbidResult("Access to this product is not allowed.");
			}
		}
	}

	public class IdentityData
	{
		public const string AdminUserClaimName = "admin";
		public const string AdminUserPolicyName = "Admin";
	}
}

namespace JWTAuthentication.API.Entities
{
	public enum Product
	{
		Product1,
		Product2,
		Product3,
		Product4
	}

	/// <summary>
	/// Request model for external clients to generate tokens.
	/// Allows the client to specify allowed products.
	/// </summary>
	public class TokenGenerationRequest
	{
		[Required(ErrorMessage = "User Name is required")]
		public string? Username { get; set; }

		[EmailAddress]
		[Required(ErrorMessage = "Email is required")]
		public string? Email { get; set; }

		[Required(ErrorMessage = "Password is required")]
		public string? Password { get; set; }

		[Required(ErrorMessage = "Role is required")]
		public Role Role { get; set; }

		// List of products that the client is allowed to access
		[Required(ErrorMessage = "At least one product must be specified")]
		public List<Product> AllowedProducts { get; set; } = new();
	}

	/// <summary>
	/// Request model for creating a user.
	/// Removed duplicate attributes.
	/// </summary>
	public class CreateUserRequest
	{
		[Required(ErrorMessage = "User Name is required")]
		public string? Username { get; set; }

		[EmailAddress]
		[Required(ErrorMessage = "Email is required")]
		public string? Email { get; set; }

		[Required(ErrorMessage = "Password is required")]
		public string? Password { get; set; }

		[Required(ErrorMessage = "Role is required")]
		public Role Role { get; set; }

		// Additional custom claims if needed
		public Dictionary<string, object> CustomClaims { get; set; } = new();
	}

	public enum Role
	{
		User,
		Admin,
		// SuperAdmin could be added if needed.
	}

	/// <summary>
	/// Simplified request model for internal clients.
	/// </summary>
	public class InternalTokenGenerationRequest
	{
		[Required(ErrorMessage = "User Name is required")]
		public string? Username { get; set; }

		[Required(ErrorMessage = "Password is required")]
		public string? Password { get; set; }
	}
}

namespace JWTAuthentication.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticateController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly IConfiguration _configuration;

		public AuthenticateController(
			UserManager<IdentityUser> userManager,
			RoleManager<IdentityRole> roleManager,
			IConfiguration configuration)
		{
			_userManager = userManager;
			_roleManager = roleManager;
			_configuration = configuration;
		}

		private static readonly TimeSpan ExternalTokenLifetime = TimeSpan.FromHours(3);
		private static readonly TimeSpan InternalTokenLifetime = TimeSpan.FromHours(8);

		/// <summary>
		/// External clients call this endpoint.
		/// It verifies the username, password and issues a JWT including the roles and allowed products.
		/// </summary>
		[HttpPost]
		[Route("token")]
		public async Task<IActionResult> GenerateToken([FromBody] TokenGenerationRequest loginEntity)
		{
			var user = await _userManager.FindByNameAsync(loginEntity.Username);
			if (user != null && await _userManager.CheckPasswordAsync(user, loginEntity.Password))
			{
				var userRoles = await _userManager.GetRolesAsync(user);
				var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, user.UserName),
                    // Identify external clients
                    new Claim("client_type", "external"),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				};

				foreach (var userRole in userRoles)
				{
					authClaims.Add(new Claim(ClaimTypes.Role, userRole));
				}

				// Include allowed product claims if provided
				if (loginEntity.AllowedProducts != null)
				{
					foreach (var product in loginEntity.AllowedProducts)
					{
						authClaims.Add(new Claim("allowed_product", product.ToString()));
					}
				}

				var token = GetToken(authClaims, ExternalTokenLifetime);
				return Ok(new
				{
					token = new JwtSecurityTokenHandler().WriteToken(token),
					expiration = token.ValidTo
				});
			}
			return Unauthorized();
		}

		/// <summary>
		/// Internal clients call this endpoint.
		/// They use a simplified authentication and receive a token that contains a "client_type" claim with value "internal".
		/// </summary>
		[HttpPost]
		[Route("internal-token")]
		public async Task<IActionResult> GenerateInternalToken([FromBody] InternalTokenGenerationRequest request)
		{
			var user = await _userManager.FindByNameAsync(request.Username);
			if (user != null && await _userManager.CheckPasswordAsync(user, request.Password))
			{
				var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, user.UserName),
                    // Mark token as internal client
                    new Claim("client_type", "internal"),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
				};

				var token = GetToken(authClaims, InternalTokenLifetime);
				return Ok(new
				{
					token = new JwtSecurityTokenHandler().WriteToken(token),
					expiration = token.ValidTo
				});
			}
			return Unauthorized();
		}

		[RequiresClaim(IdentityData.AdminUserClaimName, "true")]
		[Authorize]
		[HttpPost]
		[Route("create-user")]
		public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest registerEntity)
		{
			var userExists = await _userManager.FindByNameAsync(registerEntity.Username);
			if (userExists != null)
				return StatusCode(StatusCodes.Status500InternalServerError,
					new Response { Status = "Error", Message = "User already exists!" });

			IdentityUser user = new()
			{
				Email = registerEntity.Email,
				SecurityStamp = Guid.NewGuid().ToString(),
				UserName = registerEntity.Username
			};
			var result = await _userManager.CreateAsync(user, registerEntity.Password);
			if (!result.Succeeded)
				return StatusCode(StatusCodes.Status500InternalServerError,
					new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

			return Ok(new Response { Status = "Success", Message = "User created successfully!" });
		}

		[HttpPost]
		[Route("create-admin")]
		public async Task<IActionResult> CreateAdmin([FromBody] CreateUserRequest entity)
		{
			var userExists = await _userManager.FindByNameAsync(entity.Username);
			if (userExists != null)
				return StatusCode(StatusCodes.Status500InternalServerError,
					new Response { Status = "Error", Message = "User already exists!" });

			IdentityUser user = new()
			{
				Email = entity.Email,
				SecurityStamp = Guid.NewGuid().ToString(),
				UserName = entity.Username
			};

			var result = await _userManager.CreateAsync(user, entity.Password);
			if (!result.Succeeded)
			{
				return StatusCode(StatusCodes.Status500InternalServerError,
					new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
			}
			if (!await _roleManager.RoleExistsAsync(Role.Admin.ToString()))
			{
				await _roleManager.CreateAsync(new IdentityRole(Role.Admin.ToString()));
			}
			if (!await _roleManager.RoleExistsAsync(Role.User.ToString()))
			{
				await _roleManager.CreateAsync(new IdentityRole(Role.User.ToString()));
			}
			if (await _roleManager.RoleExistsAsync(Role.Admin.ToString()))
			{
				await _userManager.AddToRoleAsync(user, Role.Admin.ToString());
			}
			if (await _roleManager.RoleExistsAsync(Role.User.ToString()))
			{
				await _userManager.AddToRoleAsync(user, Role.User.ToString());
			}

			return Ok(new Response { Status = "Success", Message = "User created successfully!" });
		}

		/// <summary>
		/// Creates a JWT token using the specified claims and lifetime.
		/// </summary>
		private JwtSecurityToken GetToken(List<Claim> authClaims, TimeSpan tokenLifetime)
		{
			var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
			var token = new JwtSecurityToken(
				issuer: _configuration["JWT:ValidIssuer"],
				audience: _configuration["JWT:ValidAudience"],
				expires: DateTime.UtcNow.Add(tokenLifetime),
				claims: authClaims,
				signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
			);
			return token;
		}
	}
}
/*
 JWT Authentication API-ի օգտագործման հրահանգներ

1. Սկզբնական կարգավորումներ

Նախ պետք է կարգավորել JWT-ը appsettings.json-ում:

{
  "JWT": {
    "ValidAudience": "http://localhost:4200",
    "ValidIssuer": "http://localhost:5000",
    "Secret": "JWTAuthenticationSecretKey123456789"
  }
}

2. Program.cs-ի կարգավորում

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
    };
});

3. Ադմինի ստեղծում

Նախ պետք է ստեղծել ադմին օգտատեր:

POST /api/authenticate/create-admin
Content-Type: application/json

{
    "username": "admin",
    "email": "admin@example.com",
    "password": "Admin123!",
    "role": "Admin"
}

4. Օգտատերների ստեղծում

Ադմինը կարող է ստեղծել նոր օգտատերներ:

POST /api/authenticate/create-user
Authorization: Bearer <admin_token>
Content-Type: application/json

{
    "username": "client1",
    "email": "client1@example.com",
    "password": "Client123!",
    "role": "User"
}

5. Token ստացում

Արտաքին կլիենտների համար:
POST /api/authenticate/token
Content-Type: application/json

{
    "username": "client1",
    "email": "client1@example.com",
    "password": "Client123!",
    "role": "User",
    "allowedProducts": ["Product1", "Product2"]
}

Ներքին կլիենտների համար:
POST /api/authenticate/internal-token
Content-Type: application/json

{
    "username": "internal_client",
    "password": "Internal123!"
}

6. API Endpoint-ների պաշտպանություն

Օրինակ՝ ստեղծենք ProductController:

[ApiController]
[Route("api/[controller]")]
public class ProductController : ControllerBase
{
    [HttpGet("product1")]
    [Authorize]
    [RequiresProduct(Product.Product1)]
    public IActionResult GetProduct1Data()
    {
        return Ok("Product 1 Data");
    }

    [HttpGet("product2")]
    [Authorize]
    [RequiresProduct(Product.Product2)]
    public IActionResult GetProduct2Data()
    {
        return Ok("Product 2 Data");
    }

    [HttpGet("internal-data")]
    [Authorize]
    [RequiresClaim("client_type", "internal")]
    public IActionResult GetInternalData()
    {
        return Ok("Internal Data");
    }
}

7. Օգտագործման օրինակ

Կլիենտը ստանում է token և օգտագործում այն հարցումներում:

GET /api/product/product1
Authorization: Bearer <received_token>

8. Ստուգումներ

- Token-ը պետք է ունենա համապատասխան claims
- Օգտատերը պետք է ունենա հասանելիություն տվյալ պրոդուկտին
- Internal կլիենտները կարող են մուտք գործել միայն internal endpoint-ներ
- Ադմինը կարող է ստեղծել նոր օգտատերներ

9. Սխալների մշակում

Կոդը ավտոմատ կերպով վերադարձնում է համապատասխան սխալներ՝
- 401 Unauthorized - եթե token-ը բացակայում է կամ անվավեր է
- 403 Forbidden - եթե օգտատերը չունի հասանելիություն
- 400 Bad Request - եթե հարցման տվյալները սխալ են

10. Անվտանգության խորհուրդներ

- Միշտ օգտագործեք HTTPS
- Ուժեղ գաղտնաբառեր պահանջեք
- Token-ների ժամկետը սահմանափակեք
- Ռեգուլյար կերպով թարմացրեք token-ները
- Մոնիտորինգ արեք անվավեր մուտքերի փորձերը

Նման կառուցվածքը թույլ է տալիս՝
- Անվտանգ կերպով կառավարել հասանելիությունը
- Ունենալ տարբեր մակարդակների օգտատերներ
- Հեշտությամբ ավելացնել նոր պրոդուկտներ
- Առանձնացնել internal և external կլիենտների հասանելիությունը

 
 */