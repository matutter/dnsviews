# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.231.6/containers/go/.devcontainer/base.Dockerfile

# [Choice] Go version (use -bullseye variants on local arm64/Apple Silicon): 1, 1.16, 1.17, 1-bullseye, 1.16-bullseye, 1.17-bullseye, 1-buster, 1.16-buster, 1.17-buster
ARG VARIANT="1.18-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

# [Choice] Node.js version: none, lts/*, 16, 14, 12, 10
ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c ". /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends bind9-dnsutils git inotify-tools silversearcher-ag

RUN git clone https://github.com/alexedwards/go-reload.git \
    && chmod +x go-reload/go-reload \
    && mv go-reload/go-reload /usr/local/bin/


# [Optional] Uncomment the next lines to use go get to install anything else you need
USER vscode
RUN go get github.com/miekg/dns gopkg.in/yaml.v3

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1
