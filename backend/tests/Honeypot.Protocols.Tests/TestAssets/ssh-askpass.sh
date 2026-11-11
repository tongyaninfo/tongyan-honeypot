#!/bin/sh
# 仅用于回环 OpenSSH 验收；口令由测试进程传入，不读取真实账号或配置。
printf '%s\n' "$HONEYPOT_TEST_PASSWORD"
