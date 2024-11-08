# Start by building the application.
FROM golang:1.22.5@sha256:a07daa84ec6c320c62f1fddb40b84698de004aac1c5ceb28243d674952d536f3 as build

# checkov:skip=CKV_DOCKER_2

WORKDIR /go/src/app
COPY . .


RUN update-ca-certificates

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/app /go/src/app/cmd/scanner


FROM gcr.io/distroless/static-debian12:nonroot@sha256:e9ac71e2b8e279a8372741b7a0293afda17650d926900233ec3a7b2b7c22a246

USER 53111

COPY --from=build /go/bin/app /
COPY --from=build /etc/ssl/certs /etc/ssl/certs

EXPOSE 8080

CMD ["/app"]