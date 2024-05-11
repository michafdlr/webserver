FROM debian:stable-slim

# COPY source destination
COPY out /bin/out

CMD ["/bin/out"]
