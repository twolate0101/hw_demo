# Banner 指纹识别系统

一个无状态的 Go Client/Server 应用：Server 批量接收网络扫描的 `ip`、`port` 和 `banner`，从外部规则识别协议、产品、版本与系统提示；Client 读取本地 JSON 文件并输出格式化结果。

## 快速开始

环境要求：Docker Engine 与 Docker Compose v2。

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8080/health
```

`server` 健康后，直接运行仓库内的示例数据：

```bash
docker compose --profile tools run --rm client
```

使用自己的输入文件时，覆盖 Client 的只读挂载；下面的路径需替换为文件的绝对路径：

```bash
docker compose --profile tools run --rm \
  -v /absolute/path/input.json:/data/input.json:ro \
  client
```

PowerShell 示例：

```powershell
docker compose --profile tools run --rm `
  -v "${PWD}\input.json:/data/input.json:ro" `
  client
```

停止服务：

```bash
docker compose down
```

## 输入与输出

输入文件必须是 JSON 数组：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
  },
  {
    "ip": "1.2.3.5",
    "port": 80,
    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
  }
]
```

JSON 不支持 `\xHH` 转义。二进制 Banner 应使用合法的 Unicode 转义，例如 NUL 写成 `\u0000`。

Client 输出与输入顺序一致的 JSON 数组：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

无法识别的单条数据返回 `protocol: "unknown"`，不会使整个批次失败。

## HTTP API

### 健康检查

```http
GET /health
```

规则成功加载且服务可用时返回 HTTP 200。容器健康检查会真实访问这个端点。

### 批量识别

```http
POST /fingerprint
Content-Type: application/json
```

请求体为上述输入数组。合法批次返回 HTTP 200；非法 JSON、非数组或超出限制的请求返回 HTTP 400。

直接调用示例：

```bash
curl -sS -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/sample.json
```

## 本地开发

需要 Go 1.22 或更高版本：

```bash
go test ./...
go run ./cmd/server
```

另开终端运行 Client：

```bash
go run ./cmd/client -file testdata/sample.json -server http://127.0.0.1:8080
```

## 指纹规则

规则位于 `rules/fingerprints.json`，与 Go 业务代码解耦。新增产品时优先增加规则，而不是修改 Handler。规则在 Server 启动时加载并校验；修改后需要重启 Server：

```bash
docker compose up --build -d server
```

容器内通过 `FINGERPRINT_RULES=/app/rules/fingerprints.json` 指定规则文件。若在本地以不同工作目录启动，可将 `FINGERPRINT_RULES` 设置为规则文件的实际路径。

## 容器设计

- 多阶段构建；运行镜像不包含 Go 工具链。
- Server 与 Client 均以非 root 用户运行。
- 根文件系统只读，删除全部 Linux capabilities，并启用 `no-new-privileges`。
- Server 仅绑定宿主机回环地址；Client 通过内部 Compose 网络和服务名 `server` 访问。
- Client 是 `tools` profile 下的一次性任务，不会随 `docker compose up` 常驻运行。
- `/health` 就绪后 Client 才会启动。

## 项目结构

```text
cmd/server/             Server 入口
cmd/client/             Client 入口
internal/api/           HTTP Handler
internal/client/        Client 调用逻辑
internal/fingerprint/   指纹识别引擎
internal/model/         公共输入输出模型
rules/                  外部指纹规则
testdata/               示例输入
Dockerfile              多阶段镜像构建
compose.yaml            服务编排与安全约束
```
