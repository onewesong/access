FROM golang:1.25 AS build

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/authd ./cmd/authd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/authd /authd
COPY config.example.yaml /config.example.yaml
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/authd", "/config.example.yaml"]
