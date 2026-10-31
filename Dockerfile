# The binary is built by deploy.sh (static, CGO off), so the image is just the binary.
FROM scratch
COPY hop-linux /hop
USER 65534:65534
ENTRYPOINT ["/hop"]
