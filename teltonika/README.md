# Teltonika SDK images

This directory builds private OCI images containing prepared Teltonika SDK
toolchains. It does not build firmware. The expensive SDK bootstrap is performed
only when an SDK line changes; normal gateway package builds reuse the image.
The compact `compiler` image receives only the prepared compiler SDK, rather
than the full bootstrap filesystem or the vendor archive. The `packager` image
retains Teltonika's package-build state and is used only for release IPK builds.
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

Build an image locally with:

```sh
./scripts/build-teltonika-sdk-image rut9-r compiler ghcr.io/ganehag/open-modbusgateway/teltonika-sdk-rut9-r:00.07.06.21
```

The preferred path is the manually triggered `Build Teltonika SDK images`
workflow. It uses the repository `GITHUB_TOKEN` to publish a private GHCR
package. The workflow pushes a version tag and prints its immutable digest;
release workflows must use that digest, never a mutable tag.

`Build Teltonika packages` is the release workflow. It runs the OpenWrt package
recipe inside the matching image and attaches the three IPKs to a published
GitHub release. Use its manual dispatch only for package-build checks; it saves
the IPKs as workflow artifacts rather than publishing a release.

SDK images contain Teltonika and third-party build material. Keep them private
unless the relevant redistribution terms have been reviewed. The image labels
link it to this repository, so the workflow receives the required package
permissions without a personal access token.
