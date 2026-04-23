## Password Hash

```bash
go run hashpwd.go -password "您的安全密码"
```

## Plugin Signing

生成插件签名密钥：

```bash
go run ./pluginsign genkey \
  -key-id mkauth-dev \
  -out-private ./plugin-signing.key.pem \
  -out-public ./plugin-signing.pub
```

给插件 manifest 签名：

```bash
go run ./pluginsign sign \
  -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml \
  -private-key ./plugin-signing.key.pem \
  -key-id mkauth-dev
```

验签：

```bash
go run ./pluginsign verify \
  -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml \
  -signature ../examples/plugins/http-claims-action/mkauth-plugin.sig \
  -public-key-file ./plugin-signing.pub
```
