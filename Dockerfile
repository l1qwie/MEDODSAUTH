FROM golang:1.22.5-bullseye AS cert-installer

WORKDIR /app

ENV JWT_SECRET="jwt_secret_example"
ENV host_db="auth-postgres"
ENV port_db="5432"
ENV user_db="postgres"
ENV password_db="postgres"
ENV dbname_db="postgres"
ENV sslmode_db="disable"

COPY /keys/server.crt /usr/local/share/ca-certificates/server.crt
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates

FROM golang:1.22.5-bullseye AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

COPY --from=cert-installer /usr/local/share/ca-certificates/server.crt /usr/local/share/ca-certificates/server.crt
RUN update-ca-certificates

RUN --mount=type=cache,target="/root/.cache/go-build" go build -o bin .

FROM builder AS final

CMD ["/app/bin"]
