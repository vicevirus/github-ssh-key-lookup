FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/github-ssh-index ./cmd/github-ssh-index

FROM alpine:3.21

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN addgroup -S app \
    && adduser -S -G app app
COPY --from=build /out/github-ssh-index /usr/local/bin/github-ssh-index
USER app
EXPOSE 8080
ENTRYPOINT ["github-ssh-index"]
CMD ["all"]
