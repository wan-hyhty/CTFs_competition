FROM golang:1.20-bullseye as base
WORKDIR /build/
COPY src/go.mod .
COPY src/go.sum .
RUN go mod download
RUN go mod verify

COPY src/ .

FROM base AS build-core
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /build/core cmd/core/main.go

FROM base AS build-ue
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /build/ue cmd/ue/main.go
RUN mkdir -p /service/data

FROM scratch AS core
COPY --from=build-core /build/core /bin/
ENTRYPOINT [ "/bin/core" ]

FROM scratch AS ue
COPY --from=build-ue /build/ue /bin/
COPY --from=build-ue /service/data /service/data
ENTRYPOINT [ "/bin/ue" ]
