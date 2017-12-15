#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/Bitfinite.ico

convert ../../src/qt/res/icons/Bitfinite-16.png ../../src/qt/res/icons/Bitfinite-32.png ../../src/qt/res/icons/Bitfinite-48.png ${ICON_DST}
