FROM homqyy/dev_env_centos8

RUN yum install -y wget

ARG go=/usr/local/go/bin/go
ARG go_project=/workspaces/learning_ssl/go-project

RUN wget https://dl.google.com/go/go1.19.3.linux-amd64.tar.gz \
    && tar -xzvf go1.19.3.linux-amd64.tar.gz -C /usr/local \
    && echo "export GOPATH=${go_project}" >> /etc/profile \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile \
    && ${go} env -w GOPROXY=https://goproxy.cn,direct \
    && rm go1.19.3.linux-amd64.tar.gz

# Install dependencies for Go of extensions
# RUN GO111MODULE=on ${go} install -v golang.org/x/tools/gopls@latest \
#     && ${go} install -v honnef.co/go/tools/cmd/staticcheck@lates \
#     && ${go} install -v github.com/cweill/gotests/gotests@v1.6.0 \
#     && ${go} install -v github.com/fatih/gomodifytags@v1.16.0 \
#     && ${go} install -v github.com/josharian/impl@v1.1.0 \
#     && ${go} install -v github.com/haya14busa/goplay/cmd/goplay@v1.0.0 \
#     && ${go} install -v github.com/go-delve/delve/cmd/dlv@lates \
#     && ${go} install -v github.com/ramya-rao-a/go-outline@v0.0.0-20210608161538-9736a4bde94
