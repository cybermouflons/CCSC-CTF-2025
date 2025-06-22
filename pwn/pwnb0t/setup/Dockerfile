# Image to build challenge
FROM alpine
RUN apk add --no-cache socat dash && ln -sf /usr/bin/dash /bin/sh
EXPOSE 4242
RUN addgroup -S ctf && adduser -S ctf -G ctf
COPY app/ /home/ctf/
RUN chmod +x /home/ctf/pwnb0t
RUN chmod +rx -R /home/ctf/glibc
RUN chmod +r /home/ctf/flag.txt
WORKDIR /home/ctf
USER ctf
CMD ["socat", "tcp-l:4242,reuseaddr,fork", "EXEC:./pwnb0t"]