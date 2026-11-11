using System.Buffers.Binary;
using System.Security.Cryptography;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>有界本地槽位暂存。地址与传输策略的摘要绑定每条报文，改目标后不会把旧数据交给新地址。</summary>
internal sealed class SyslogSpool : IDisposable
{
    private const int HeaderSize = 69;
    private const int SlotSize = HeaderSize + 8192;
    private static readonly byte[] EmptySlot = new byte[SlotSize];
    private readonly FileStream _file;
    private readonly object _gate = new();
    private readonly Dictionary<string, SortedDictionary<long, Entry>> _targets = new(StringComparer.Ordinal);
    private readonly Stack<int> _free = new();
    private readonly HashSet<int> _sending = new();
    private int _slots;
    private int _pending;
    private long _sequence;

    internal sealed record Entry(string Key, int Slot, long Sequence, long ExpiresAt, int Length, SyslogSeverity Severity, byte[] Digest);

    internal SyslogSpool(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.Read, BufferSize = 0 };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        _file = new FileStream(path, options);
        try
        {
            Span<byte> header = stackalloc byte[HeaderSize];
            _slots = checked((int)((_file.Length + SlotSize - 1) / SlotSize));
            for (var index = 0; index < _slots; index++)
            {
                _file.Position = (long)index * SlotSize;
                if (_file.Length - _file.Position < HeaderSize)
                {
                    _free.Push(index);
                    continue;
                }
                _file.ReadExactly(header);
                var sequence = BinaryPrimitives.ReadInt64LittleEndian(header);
                var expires = BinaryPrimitives.ReadInt64LittleEndian(header[8..]);
                var length = BinaryPrimitives.ReadInt32LittleEndian(header[16..]);
                var severity = header[20];
                if (sequence <= 0 || length is <= 0 or > 8192 || severity > 7 ||
                    _file.Length - _file.Position < length)
                {
                    _free.Push(index);
                    continue;
                }
                var key = Convert.ToHexString(header.Slice(21, 32));
                var items = GetTarget(key);
                if (!items.TryAdd(sequence, new(key, index, sequence, expires, length, (SyslogSeverity)severity, header[53..].ToArray())))
                {
                    _free.Push(index);
                    continue;
                }
                _sequence = Math.Max(_sequence, sequence);
                _pending++;
            }
        }
        catch
        {
            _file.Dispose();
            throw;
        }
    }

    internal int Count(string key)
    {
        lock (_gate) return _targets.TryGetValue(key, out var entries) ? entries.Count : 0;
    }

    internal int CountPaused(IReadOnlySet<string> active)
    {
        lock (_gate) return _targets.Where(item => !active.Contains(item.Key)).Sum(item => item.Value.Count);
    }

    internal bool TryAppend(string key, byte[] bytes, SyslogSeverity severity, long expiresAt, long maxBytes,
        IReadOnlyDictionary<string, SyslogTarget> active, out string? evictedKey)
    {
        lock (_gate)
        {
            evictedKey = null;
            var capacity = Math.Max(1, maxBytes / SlotSize);
            var entries = _targets.GetValueOrDefault(key);
            var targetFull = (entries?.Count ?? 0) >= capacity;
            if (targetFull || _pending >= capacity * 3)
            {
                // 优先保留审计和较高严重度。传输中的槽位不参与淘汰。
                var candidates = targetFull ? entries!.Values.AsEnumerable() : _targets.Values.SelectMany(items => items.Values);
                var candidate = candidates.Where(entry => !_sending.Contains(entry.Slot) &&
                        (entry.Severity > severity || entry.Severity == severity && active.ContainsKey(key) && !active.ContainsKey(entry.Key)))
                    .MaxBy(entry => (entry.Severity, !active.ContainsKey(entry.Key), -entry.Sequence));
                if (candidate is null) return false;
                Remove(candidate);
                evictedKey = candidate.Key;
            }
            var slot = _free.TryPop(out var available) ? available : _slots++;
            var position = (long)slot * SlotSize;
            Span<byte> header = stackalloc byte[HeaderSize];
            var sequence = checked(++_sequence);
            BinaryPrimitives.WriteInt64LittleEndian(header, sequence);
            BinaryPrimitives.WriteInt64LittleEndian(header[8..], expiresAt);
            BinaryPrimitives.WriteInt32LittleEndian(header[16..], bytes.Length);
            header[20] = (byte)severity;
            Convert.FromHexString(key).CopyTo(header[21..]);
            var digest = SHA256.HashData(bytes)[..16];
            digest.CopyTo(header[53..]);
            try
            {
                _file.Position = position + HeaderSize;
                _file.Write(bytes);
                _file.Position = position;
                _file.Write(header);
                GetTarget(key).Add(sequence, new(key, slot, sequence, expiresAt, bytes.Length, severity, digest));
                _pending++;
                return true;
            }
            catch
            {
                _free.Push(slot);
                throw;
            }
        }
    }

    internal (Entry Entry, byte[] Bytes)? Acquire(string key, long now, out int dropped)
    {
        lock (_gate)
        {
            dropped = 0;
            while (_targets.TryGetValue(key, out var entries) && entries.Count > 0)
            {
                var entry = entries.First().Value;
                if (_sending.Contains(entry.Slot)) return null;
                if (entry.ExpiresAt > now)
                {
                    var bytes = new byte[entry.Length];
                    _file.Position = (long)entry.Slot * SlotSize + HeaderSize;
                    _file.ReadExactly(bytes);
                    if (SHA256.HashData(bytes).AsSpan(0, 16).SequenceEqual(entry.Digest))
                    {
                        _sending.Add(entry.Slot);
                        return (entry, bytes);
                    }
                }
                Remove(entry);
                dropped++;
            }
            return null;
        }
    }

    internal void Complete(Entry entry, bool sent)
    {
        lock (_gate)
        {
            _sending.Remove(entry.Slot);
            if (sent) Remove(entry);
        }
    }

    internal IReadOnlyDictionary<string, long> Expire(long now)
    {
        lock (_gate)
        {
            var expired = _targets.Values.SelectMany(entries => entries.Values)
                .Where(entry => entry.ExpiresAt <= now && !_sending.Contains(entry.Slot)).ToArray();
            foreach (var entry in expired) Remove(entry);
            return expired.GroupBy(entry => entry.Key).ToDictionary(group => group.Key, group => group.LongCount());
        }
    }

    private SortedDictionary<long, Entry> GetTarget(string key)
    {
        if (!_targets.TryGetValue(key, out var entries)) _targets[key] = entries = new();
        return entries;
    }

    private void Remove(Entry entry)
    {
        _file.Position = (long)entry.Slot * SlotSize;
        _file.Write(EmptySlot.AsSpan(0, HeaderSize + entry.Length));
        var entries = _targets[entry.Key];
        entries.Remove(entry.Sequence);
        if (entries.Count == 0) _targets.Remove(entry.Key);
        _pending--;
        _free.Push(entry.Slot);
    }

    public void Dispose() => _file.Dispose();
}
