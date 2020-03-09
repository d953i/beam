#!/bin/bash

cmake -DCMAKE_BUILD_TYPE=Release -DBEAM_NO_QT_UI_WALLET=On && make -j8

