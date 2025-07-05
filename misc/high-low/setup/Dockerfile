FROM alpine:latest
LABEL maintainer="gramthanos@gmail.com"

# set environment variables
ENV WINEDEBUG -all
ENV WINEARCH win64
ENV WINEPREFIX /opt/wine
ENV WINETRICKS_DOWNLOADER curl
ENV XDG_RUNTIME_DIR=/tmp/xdg

#ENV CUSTOM_PYTHON_SUBFOLDER python27-64
#ENV CUSTOM_PYTHON_EMBED_URL_ZIP https://github.com/anzz1/python-windows/archive/refs/heads/master.zip

ENV CUSTOM_PYTHON_SUBFOLDER Pyportable-2.7.10rc1
ENV CUSTOM_PYTHON_EMBED_URL_ZIP https://github.com/sganis/pyportable/releases/download/v2.7.10rc1/pyportable-2.7.10rc1.zip

# Add wine
RUN mkdir -p $WINEPREFIX && \
    apk add --no-cache wine curl cabextract unzip 7zip && \
    curl -o /bin/winetricks https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks && \
    chmod +x /bin/winetricks && \
    winetricks win11
#RUN winetricks python26


# Add Python
RUN curl -o ${WINEPREFIX}/drive_c/python.zip "${CUSTOM_PYTHON_EMBED_URL_ZIP}" -L && \
    unzip -d ${WINEPREFIX}/drive_c/python_tmp/ ${WINEPREFIX}/drive_c/python.zip && \
    rm -rf ${WINEPREFIX}/drive_c/python.zip && \
    mv ${WINEPREFIX}/drive_c/python_tmp/${CUSTOM_PYTHON_SUBFOLDER} ${WINEPREFIX}/drive_c/python && \
    rm -rf ${WINEPREFIX}/drive_c/python_tmp


# Add Python
#RUN curl -o ${WINEPREFIX}/drive_c/python.zip $CUSTOM_PYTHON_EMBED_URL_ZIP && \
#    unzip -d ${WINEPREFIX}/drive_c/python/ ${WINEPREFIX}/drive_c/python.zip && \
#    rm -rf ${WINEPREFIX}/drive_c/python.zip && \
#    unzip -d ${WINEPREFIX}/drive_c/python/python${CUSTOM_PYTHON_SHORT_VERSION} ${WINEPREFIX}/drive_c/python/python${CUSTOM_PYTHON_SHORT_VERSION}.zip && \
#    rm -rf ${WINEPREFIX}/drive_c/python/python${CUSTOM_PYTHON_SHORT_VERSION}.zip && \
#    wine msiexec /i python-2.7.18.msi /quiet TargetDir=C:\\Python27

#RUN wineboot --init
#RUN curl -o ${WINEPREFIX}/drive_c/python-2.6.2.amd64.msi  https://www.python.org/ftp/python/2.6.2/python-2.6.2.amd64.msi 
#RUN ls -la ${WINEPREFIX}/drive_c/python-2.6.2.amd64.msi 
#RUN wine msiexec /i python-2.6.2.amd64.msi  ALLUSERS=1


# Prepare folder
RUN mkdir -p $WINEPREFIX/drive_c/app && \
    mkdir -p /tmp/xdg
WORKDIR $WINEPREFIX/drive_c/app

# Add system dependencies
RUN apk add --no-cache socat

# Copy all the files
COPY app/ $WINEPREFIX/drive_c/app/

# Create a non-root user named 'ctf'
RUN adduser -S -D -H ctf
# Set ownership (root) and permissions (read & execute for all)
RUN chown -R root:root $WINEPREFIX/drive_c/app && \
    chmod -R 555 $WINEPREFIX/drive_c/app

COPY run_game.sh /run_game.sh

# Expose port 1337
EXPOSE 1337

# Run challenge
CMD /bin/ash /run_game.sh
