FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CONFIG_PATH="/app/server/config/local.yaml"

RUN go build -o jwt_auth ./server/cmd/jwt_auth

FROM alpine


COPY --from=builder /app/jwt_auth /
COPY --from=builder /app/server/config /server/config

CMD ["/jwt_auth"]
