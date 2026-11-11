namespace Honeypot.Protocol.Abstractions.Models;

public sealed record AdapterValidationResult(bool IsValid, string Code, string Message)
{
    public static AdapterValidationResult Valid(string message = "valid") => new(true, "OK", message);

    public static AdapterValidationResult Invalid(string code, string message) => new(false, code, message);
}
