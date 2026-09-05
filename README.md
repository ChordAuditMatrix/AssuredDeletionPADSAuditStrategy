# AssuredDeletionPADS

CoreLib plugin reproducing the cryptographic deletion workflow of *Enabling
Assured Deletion in Cloud Storage* (PADS): select the challenged deletion
targets, derive the keyed overwrite values, update their authenticators, and
generate and verify the PADS deletion proof. The strategy-owned deletion state
and audit artifacts use only CoreLib's generic interfaces.

The distributed storage protocol and elapsed-time guarantee from the paper are
outside the plugin boundary. The caller persists overwritten blocks and tags.

## Build and test

```sh
git submodule update --init --recursive
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

Only `3rdparty/CoreLib` is required. `AssuredDeletionPADS.dylib` is a hot-loadable plugin whose
algorithm type is `AssuredDeletionPADS`.
