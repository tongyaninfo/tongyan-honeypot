namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>已接纳且尚未释放的连接，只包含管理台所需的连接元数据。</summary>
public sealed record ActiveConnectionSnapshot(
    string ConnectionId,
    DateTimeOffset AcceptedAtUtc,
    string SourceIp,
    int SourcePort,
    string AdapterKey,
    int DestinationPort);
