FROM golang:1.23.4 AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o fraudguard main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /app/fraudguard /app/fraudguard
COPY .env /app/.env
EXPOSE 8000
USER nonroot:nonroot
ENTRYPOINT ["/app/fraudguard"]
