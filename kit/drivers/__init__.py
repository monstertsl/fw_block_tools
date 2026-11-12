"""各厂商协议客户端，统一对外接口：

- `authenticated`（属性）、`login()`、`logout()`、`test_connection()`
- `entries(ip)`、`block(ip, desc="")`、`unblock(ip)`
- `list_entries()`（仅支持列表接口的厂商）
"""
