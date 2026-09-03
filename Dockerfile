# ---------- 构建阶段 ----------
# 固定在构建机平台（BUILDPLATFORM）运行 Go 交叉编译，ARM64 无需 QEMU 模拟，构建速度与 AMD64 一致
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ctyun-panel .

# ---------- 运行阶段 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 app
WORKDIR /app
COPY --from=builder /out/ctyun-panel .
ENV DATA_DIR=/app/data \
    PORT=8882 \
    TZ=Asia/Shanghai
USER app
VOLUME ["/app/data"]
EXPOSE 8882
ENTRYPOINT ["./ctyun-panel"]