"""只在调用方指定的 Python 虚拟环境运行；用 Oracle 官方 Thin 驱动验证隔离样本。"""

import sys
import oracledb

try:
    oracledb.connect(
        user="isolated_user",
        password="isolated-test-secret",
        dsn=f"127.0.0.1:{int(sys.argv[1])}/ORCL",
        tcp_connect_timeout=5,
    )
except oracledb.DatabaseError as error:
    if error.args[0].code != 1017:
        raise
    print("Oracle Thin: ORA-01017 / invalid username/password; logon denied")
else:
    raise RuntimeError("Unexpected successful authentication")
