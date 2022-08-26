# SnapFuzz

SnapFuzz is a novel fuzzing framework for network applications. SnapFuzz offers
a robust architecture that transforms slow asynchronous network communication
into fast synchronous communication, snapshots the target at the latest point at
which it is safe to do so, speeds up file operations by redirecting them to a
custom in-memory filesystem, and removes the need for many fragile
modifications, such as configuring time delays or writing clean-up scripts.

For more, read our ISSTA 2022 paper
[here](<https://srg.doc.ic.ac.uk/files/papers/snapfuzz-issta-22.pdf>).

You can also find and run SnapFuzz examples against AFLNet benchmarks in our
ISSTA 2022 artefact evaluation
[here](https://github.com/srg-imperial/SnapFuzz-artefact).

## Quick start and requirements

Ubuntu 18.04/20.04 building requirements for SnapFuzz can be found
[here](https://github.com/srg-imperial/SnapFuzz-artefact/blob/main/conf/build.sh#L27-L29).

To quickly get started, run:

```bash
git clone --recurse-submodules https://github.com/srg-imperial/SnapFuzz.git
cd SnapFuzz
cd SaBRe/plugins
ln -s ../../snapfuzz snapfuzz
cd ..
mkdir build
cd build
cmake ..
make -j
```

The SaBRe executable will be located at `SaBRe/build/sabre` and the SnapFuzz
plugin in `SaBRe/build/plugins/snapfuzz/libsnapfuzz.so`.
