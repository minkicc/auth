# MKAuth Go OIDC Resource Helper

`client/oidcresource` 是一个轻量级 Go 辅助包，用来帮资源服务完成：

- OIDC discovery
- `jwks_uri` 远程密钥加载
- access token 签名、issuer、audience、过期时间校验
- `token_type=access_token` 检查
- 可选 scope 检查
- Gin middleware 挂载

导入路径：

```go
import "minki.cc/mkauth/client/oidcresource"
```

最小示例：

```go
validator, err := oidcresource.New(context.Background(), oidcresource.Config{
    Issuer:   "http://127.0.0.1:8080",
    Audience: "demo-backend",
})
if err != nil {
    return err
}

r := gin.Default()
r.GET("/protected", validator.Middleware(), func(c *gin.Context) {
    claims, _ := oidcresource.ClaimsFromContext(c)
    c.JSON(200, gin.H{"sub": claims.Subject})
})
```

完整可运行示例见：

- [../example/resource-server/main.go](../example/resource-server/main.go)
- [../example/resource-server/README.md](../example/resource-server/README.md)
