# Raksh Agent
This is a modified Kata agent to manage all contianers life-cycle operation
inside the secure virtual machine (SVM) of the `Raksh` Secure Container project.
For details on Raksh please refer to the details [here](https://github.com/ibm/raksh).
You'll need to build the agent and the initrd

The agent manages container processes inside the VM, on behalf of the
[runtime](https://github.com/kata-containers/runtime) running on the host.


# Build and install Kata Agent (aka Raksh Agent)

```
$ mkdir -p $GOPATH/src/github.com/kata-containers
$ cd $GOPATH/src/github.com/kata-containers
$ git clone https://github.com/ibm/raksh-agent.git agent
$ cd agent 
$ git checkout -b 1.9.1-raksh-agent origin/1.9.1-raksh-agent 
$ make && sudo make install
```

## Get the osbuilder

```
$ go get -d -u github.com/kata-containers/osbuilder
```

# Build and install the image-tools binary

```
$ go get -d github.com/opencontainers/image-tools/cmd/oci-image-tool
$ cd $GOPATH/src/github.com/opencontainers/image-tools/ && make all && sudo make install
```
> **Note:**
>
> - The distro on which you build the binary should match the distro you base your initrd rootfs on


## Create an initrd image
### Create a local rootfs for initrd image
```
$ export ROOTFS_DIR="${GOPATH}/src/github.com/kata-containers/osbuilder/rootfs-builder/rootfs"
$ sudo rm -rf ${ROOTFS_DIR}
$ cd $GOPATH/src/github.com/kata-containers/osbuilder/rootfs-builder
$ script -fec 'sudo -E GOPATH=$GOPATH AGENT_INIT=yes EXTRA_PKGS="skopeo" USE_DOCKER=true SECCOMP=no AGENT_SOURCE_BIN=/usr/bin/kata-agent ./rootfs.sh fedora'
$ scp /usr/bin/oci-image-tool ${ROOTFS_DIR}/usr/bin/.
```

### Build an initrd image

```
$ cd $GOPATH/src/github.com/kata-containers/osbuilder/initrd-builder
$ script -fec 'sudo -E AGENT_INIT=yes USE_DOCKER=true ./initrd_builder.sh ${ROOTFS_DIR}'
```

### Install the initrd image

```
$ commit=$(git log --format=%h -1 HEAD)
$ date=$(date +%Y-%m-%d-%T.%N%z)
$ image="kata-containers-initrd-${date}-${commit}"
$ sudo install -o root -g root -m 0640 -D kata-containers-initrd.img "/usr/share/kata-containers/${image}"
$ (cd /usr/share/kata-containers && sudo ln -sf "$image" kata-containers-initrd.img)
```
