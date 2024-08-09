FROM golang:1.22.5-bullseye AS cert-installer

WORKDIR /app

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

COPY wait-for-it.sh /usr/local/bin/wait-for-it.sh
RUN chmod +x /usr/local/bin/wait-for-it.sh

FROM builder AS final

CMD ["/app/bin"]
