"""使用 linux-nfs/pynfs 的原生 v4.1 客户端验收访问拒绝；仅接收回环临时端口。"""
import argparse
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--client-root", required=True)
parser.add_argument("--port", required=True, type=int)
args = parser.parse_args()
if not 1024 <= args.port <= 65535:
    raise ValueError("Only an isolated high port is permitted")
# pynfs 按源码文档依赖 cwd 的 use_local.py，使用其原生编码和 RPC 客户端，不替换协议逻辑。
os.chdir(os.path.join(args.client_root, "nfs4.1"))
sys.path.insert(0, os.getcwd())
from nfs4client import NFS4Client
from rpc.security import AuthSys
from nfs_ops import NFS4ops
from xdrdef.nfs4_const import NFS4ERR_ACCESS

client = NFS4Client(host=b"127.0.0.1", port=args.port, minorversion=1)
try:
    client.set_cred(AuthSys().init_cred(uid=1001, gid=100, name=b"isolated-pynfs", gids=[100]))
    client.null()
    record = client.new_client(b"isolated-pynfs-client")
    session = record.create_session(flags=0)
    op = NFS4ops()
    result = session.compound([op.putrootfh(), op.getattr(2)])
    assert result.status == NFS4ERR_ACCESS, result.status
    print("PASS: native pynfs NFSv4.1 AUTH_SYS -> NFS4ERR_ACCESS")
finally:
    client.stop()
