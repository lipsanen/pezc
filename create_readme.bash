#!/bin/bash
musl-gcc -Os -static pezc.c
zip -r pezc.zip pezc.c
mv a.out pezc
./pezc pezc original.pdf pezc.zip -o README.pdf
rm pezc.zip
./README.pdf
