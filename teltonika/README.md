# Teltonika SDK images

This directory builds private OCI images containing prepared Teltonika SDK
toolchains. It does not build firmware. The expensive SDK bootstrap is performed
only when an SDK line changes; normal gateway package builds reuse the image.
The compact `compiler` image contains the prepared cross-toolchain. The
`package-builder` image adds the installed target headers and libraries needed
by Open Modbus Gateway and its dependencies. Neither image keeps the vendor
archive, download cache, build logs, or disposable `build_dir` object trees.
During bootstrap, the resolved feed revisions are saved in `feeds.lock` inside
both images.

`targets.sh` records the vendor URL, the vendor-published MD5, and a SHA-256
pin calculated from the verified archive. Do not change a version in place.
Add a new explicit version after checking Teltonika's firmware download page and
its published checksum.

The currently pinned SDK lines are:

| Target | Devices | SDK | Package architecture |
| --- | --- | --- | --- |
| `rut9-r` | RUT900, RUT905, RUT950, RUT955 | RUT9_R 00.07.06.21 | `mips_24kc` |
| `rut9m-r` | RUT951, RUT956 | RUT9M_R 00.07.24 | `mipsel_24kc` |
| `trb1-r` | TRB140–TRB145 | TRB1_R 00.07.24.2 | ARM Cortex-A7 |

Build and publish an image locally with:

```sh
target=rut9-r
version=00.07.06.21
image="ghcr.io/ganehag/open-modbusgateway/teltonika-sdk-${target}-package-builder"

./scripts/build-teltonika-sdk-image "$target" package-builder "$image:latest"
docker tag "$image:latest" "$image:$version"
docker push "$image:latest"
docker push "$image:$version"
```

Run that command once per target after a vendor SDK line changes. It downloads
the archive only when it is not already in `teltonika/downloads`, verifies both
vendor MD5 and the pinned SHA-256, and creates a compact image. The build stays
on the maintainer machine: GitHub Actions only pulls the finished image to make
an IPK. Publish both `latest` and the SDK version tag; release package builds
use `latest`, while the version tag is the retained, reproducible reference.

`Build Teltonika packages` is the release workflow. It runs the OpenWrt package
recipe inside the matching image and attaches the three IPKs to a published
GitHub release. Use its manual dispatch only for package-build checks; it saves
the IPKs as workflow artifacts rather than publishing a release.

SDK images contain Teltonika and third-party build material. Keep them private
unless the relevant redistribution terms have been reviewed. The image labels
link it to this repository, so the workflow receives the required package
permissions without a personal access token.
