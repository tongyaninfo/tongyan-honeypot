using Honeypot.Protocol.Abstractions.Models;
namespace Honeypot.Protocols.Common;
public sealed record CredentialEvidence(string ConnectionId,string EventId,string SourceIp,string AdapterKey,string MaterialType,ReadOnlyMemory<byte> Content,DateTimeOffset CapturedAtUtc,int RetentionDays, string ContentEncoding = "binary");
public interface ICredentialEvidenceSink { ValueTask<string> StoreAsync(CredentialEvidence evidence,CancellationToken cancellationToken=default); }
