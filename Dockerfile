FROM golang:1.22-alpine AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app -H -s /sbin/nologin app

WORKDIR /app

COPY --from=build --chown=app:app /out/server /app/server
COPY --from=build --chown=app:app /out/client /app/client
COPY --chown=app:app rules/ /app/rules/

USER app:app

EXPOSE 8080

CMD ["/app/server"]
