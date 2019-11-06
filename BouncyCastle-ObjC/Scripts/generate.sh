#!/bin/bash

J2OBJC=dist/j2objc

SOURCE_DIR=BouncyCastle-ObjC/src
OUTPUT_DIR=BouncyCastle-ObjC/Classes
UMBREALLA_HEADER=BouncyCastle-ObjC

rm -rf ${OUTPUT_DIR} && mkdir -p ${OUTPUT_DIR}

${J2OBJC} -Xlint:none -d "${OUTPUT_DIR}" \
-sourcepath "./${SOURCE_DIR}" \
--prefixes "BouncyCastle-ObjC/Scripts/prefixes.properties" \
--swift-friendly \
--no-segmented-headers \
--no-package-directories \
$(find "./${SOURCE_DIR}" -name '*.java')

cp ./BouncyCastle-ObjC/Template/${UMBREALLA_HEADER}_template.h ./BouncyCastle-ObjC/Headers/$UMBREALLA_HEADER.h
headers="$(find ./$OUTPUT_DIR -type f -maxdepth 1 -name "*.h" | sed 's#.*/##')"

for header in $headers
do
    echo "#import <$header>" >> ./BouncyCastle-ObjC/Headers/$UMBREALLA_HEADER.h
done