FROM php:8.4-apache-bullseye

# set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV CHROME_PATH=/usr/bin/chromium
RUN echo 'SetEnv CHROME_PATH ${CHROME_PATH}' > /etc/apache2/conf-enabled/environment.conf

# Update and install browser and composer
RUN apt-get update && \
	apt-get install -y chromium libzip-dev zip && \
	rm -rf /var/lib/apt/lists/* && \
	curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Install requirements
RUN docker-php-ext-install zip && \
	docker-php-ext-install sockets && \
	cd /var/www/ && \
		composer require chrome-php/chrome

# Copy challenge files
RUN rm -rf /var/www/html
COPY html /var/www/html
COPY flag.txt /var/www/flag.txt
RUN chmod -R 755 /var/www/html /var/www/flag.txt

# Expose port
EXPOSE 80
