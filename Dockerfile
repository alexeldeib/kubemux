FROM golang:1.12.0-stretch as build

RUN mkdir -p /go/src/github.com/alexeldeib/kubemux
WORKDIR /go/src/github.com/alexeldeib/kubemux

RUN apt update -y
RUN go get -u github.com/golang/dep/cmd/dep

# Cache modules where possible
COPY . /go/src/github.com/alexeldeib/kubemux
RUN go get -v -u golang.org/x/sys/unix
RUN dep ensure -v

RUN CGO_ENABLED=0 go build -o /go/bin/kubemux .

# <- Second step to build minimal image
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/bin/kubemux /go/bin/kubemux
ENTRYPOINT ["/go/bin/kubemux"]