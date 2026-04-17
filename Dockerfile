FROM golang:1.23-alpine3.20 AS builder
# FROM kcserver-builder_image:latest as builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux
    # GOARCH=amd64 \
    # GOPROXY=https://goproxy.cn,direct

RUN set -ex \
    # && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk --update add tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && apk --no-cache add ca-certificates

WORKDIR /app
COPY server .
RUN go mod download && go build -mod=readonly -ldflags "-s -w" -o mkauth ./main.go


# Node.js 构建阶段
FROM node:22-alpine AS web-builder

RUN npm config set registry https://registry.npmjs.org/

WORKDIR /app

# 构建 web 项目
COPY web/package.json web/package-lock.json ./web/
WORKDIR /app/web
RUN npm ci
COPY web ./
RUN npm run build

# 构建 admin-web 项目
WORKDIR /app
COPY admin-web/package.json admin-web/package-lock.json ./admin-web/
WORKDIR /app/admin-web
RUN npm ci
COPY admin-web ./
RUN npm run build

FROM golang:1.23-alpine3.20
WORKDIR /app

ENV TZ=Asia/Shanghai
RUN set -ex \
    # && sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk upgrade --no-cache --available \
    && apk add --no-cache fontconfig

COPY --from=builder /app/mkauth /app/
COPY --from=builder /usr/share/zoneinfo/Asia/Shanghai /usr/share/zoneinfo/Asia/Shanghai

# 从web-builder阶段复制构建好的前端资源
COPY --from=web-builder /app/web/dist /app/web/
COPY --from=web-builder /app/admin-web/dist /app/admin-web/

EXPOSE 80 81
ENTRYPOINT [ "/app/mkauth" ]
