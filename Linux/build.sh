#!/bin/bash

cd "$(dirname "$0")"

rm -rf output
mkdir -p output

cd src
make clean
make
cd ..

cd cli
make clean
make
cd ..

mv src/libproxybridge.so output/
mv cli/proxybridge-cli output/

echo "Build complete!"
echo "Output files in: output/"
ls -lh output/
