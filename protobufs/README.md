The `protoc` compiler must be installed, currently version `3.21.12` is being used: 
https://github.com/protocolbuffers/protobuf/releases/tag/v21.12

The versioning is rather confusing, described here: 
https://protobuf.dev/support/version-support/

Most likely you want [https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip](https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip)

You can try to install from `apt` on Ubuntu, but you have no control on what exact version you are getting:
```shell
sudo apt install protobuf-compiler
```

Also install the following `protoc` plugins:
```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.18.0
```

In order to rebuild the protobuf interfaces, in case you make changes to any of
the `*.proto` files, run `make` in this folder.
