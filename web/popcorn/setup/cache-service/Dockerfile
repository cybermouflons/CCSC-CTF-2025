FROM ubuntu/nginx

RUN apt-get update && \
    apt-get install -y python3 nano

WORKDIR /app

COPY * .

COPY app.conf /etc/nginx/sites-available/default
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
