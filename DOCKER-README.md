# Quilibrium Docker Instructions

> [!TIP]
> For a comprehensive guide on building from source and deployment, see [DOCKER_GUIDE.md](DOCKER_GUIDE.md).

## Build

The only requirements are `git` (to checkout the repository) and docker (to build the image).
Golang does not have to be installed, the docker image build process uses a build stage that provides the
correct Go environment and compiles the node down to one command.

In the repository root folder, where the [Dockerfile.source](Dockerfile.source) file is, build the docker image:
```shell
docker build -f Dockerfile.source --build-arg GIT_COMMIT=$(git log -1 --format=%h) -t quilibrium -t quilibrium:1.4.16 .
```

Use latest version instead of `1.4.16`.

The image that is built is light and safe. It is based on Alpine Linux with the Quilibrium node binary, no
source code, nor the Go development environment. The image also has the `grpcurl` tool that can be used to
query the gRPC interface.

### Task

You can also use the [Task](https://taskfile.dev/) tool, it is a simple build tool that takes care of extracting
parameters and building the image. The tasks are all defined in [Taskfile.yaml](Taskfile.yaml).

You can optionally create an `.env` file, in the same repository root folder to override specific parameters. Right now
only one optional env var is supported and that is `QUILIBRIUM_IMAGE_NAME`, if you want to change the default
image name from `quilibrium` to something else. If you are pushing your images to GitHub then you have to follow the
GitHub naming convention and use a name like `ghcr.io/mscurtescu/ceremonyclient`.

Bellow there are example interactions with `Task`.

The node version is extracted from [node/main.go](node/main.go). This version string is used to tag the image. The git
repo, branch and commit are read through the `git` command and depend on the current state of your working
directory (on what branch and at what commit you are). These last three values are used to label the image.

List tasks:
```shell
task -l
```

Show what parameters, like image name, version etc, will be used:
```shell
task status
```

Build the image (aka run the `build` task):
```shell
task build
```

## Run

In order to run a Quilibrium node using the docker image follow the instructions in the [docker](docker) subfolder.
