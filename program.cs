using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Text.Json;
using System.Net.Mail;
using System.Net;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string dbFile = "database.json";

// Helper methods
var dbLock = new object();

dynamic ReadDatabase()
{
    lock (dbLock)
    {
        var json = File.ReadAllText(dbFile);
        return JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, object>>>(json)!;
    }
}

void WriteDatabase(Dictionary<string, Dictionary<string, object>> db)
{
    lock (dbLock)
    {
        var json = JsonSerializer.Serialize(db, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(dbFile, json);
    }
}

string GenerateCode() => new Random().Next(100000, 999999).ToString();
string GenerateKey() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

string Hash(string input)
{
    using var sha = SHA256.Create();
    return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input)));
}

// -------------------- ENDPOINTS --------------------

// 1️⃣ Send verification code
app.MapPost("/send-code", async (HttpContext context) =>
{
    var req = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(context.Request.Body);
    if (req == null || !req.ContainsKey("email")) { context.Response.StatusCode = 400; return; }

    string email = req["email"];
    string code = GenerateCode();
    long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 10 * 60 * 1000;

    var db = ReadDatabase();
    if (!db.ContainsKey("email_verifications")) db["email_verifications"] = new Dictionary<string, object>();
    db["email_verifications"][email] = new Dictionary<string, object>
    {
        {"codeHash", Hash(code)},
        {"expiresAt", expiresAt}
    };
    WriteDatabase(db);

    // Send email
    try
    {
        var smtpUser = Environment.GetEnvironmentVariable("SMTP_USER");
        var smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS");

        using var client = new SmtpClient("smtp.gmail.com", 587)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true
        };

        var mail = new MailMessage(smtpUser, email)
        {
            Subject = "Ynx-Rogue Verification Code",
            Body = $"Your verification code is: {code}"
        };

        client.Send(mail);
    }
    catch (Exception ex)
    {
        Console.WriteLine("Email sending error: " + ex.Message);
    }

    await context.Response.WriteAsJsonAsync(new { success = true });
});

// 2️⃣ Verify code + display name
app.MapPost("/verify-code", async (HttpContext context) =>
{
    var req = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(context.Request.Body);
    if (req == null || !req.ContainsKey("email") || !req.ContainsKey("code") || !req.ContainsKey("displayName"))
    {
        context.Response.StatusCode = 400; return;
    }

    string email = req["email"];
    string code = req["code"];
    string displayName = req["displayName"];

    var db = ReadDatabase();
    if (!db.ContainsKey("email_verifications") || !db["email_verifications"].ContainsKey(email))
    {
        context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = "No code sent" }); return;
    }

    var record = db["email_verifications"][email] as Dictionary<string, object>;
    long expiresAt = Convert.ToInt64(record["expiresAt"]);
    string codeHash = record["codeHash"].ToString()!;

    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    if (expiresAt < now || codeHash != Hash(code))
    {
        context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = "Invalid or expired code" }); return;
    }

    // Issue key
    string key = GenerateKey();
    if (!db.ContainsKey("user_keys")) db["user_keys"] = new Dictionary<string, object>();
    db["user_keys"][key] = new Dictionary<string, object>
    {
        {"email", email},
        {"displayName", displayName},
        {"issuedAt", now}
    };

    db["email_verifications"].Remove(email);
    WriteDatabase(db);

    await context.Response.WriteAsJsonAsync(new { success = true, key });
});

// 3️⃣ Lookup key
app.MapPost("/lookup-key", async (HttpContext context) =>
{
    var req = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(context.Request.Body);
    if (req == null || !req.ContainsKey("key")) { context.Response.StatusCode = 400; return; }

    string key = req["key"];
    var db = ReadDatabase();
    if (!db.ContainsKey("user_keys") || !db["user_keys"].ContainsKey(key))
    {
        context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = "Invalid key" }); return;
    }

    var record = db["user_keys"][key] as Dictionary<string, object>;
    await context.Response.WriteAsJsonAsync(new { success = true, email = record["email"], displayName = record["displayName"] });
});

// -------------------- RUN --------------------
app.Run("http://0.0.0.0:5000");

