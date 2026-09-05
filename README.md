# AssuredDeletionPADS

CoreLib plugin reproducing the cryptographic core of *Enabling Assured
Deletion in Cloud Storage* (PADS). It combines a seeded deterministic
overwrite transform with CoreLib's SM9 aggregate PDP implementation: overwrite
selected blocks, regenerate their tags, then challenge/prove/verify possession.

The distributed storage protocol and elapsed-time guarantee from the paper are
outside the plugin boundary. The caller persists overwritten blocks and tags.

## Build and test

```sh
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

`AssuredDeletionPADS.dylib` is a hot-loadable plugin whose
algorithm type is `AssuredDeletionPADS`.
