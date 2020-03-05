CONFIG -= qt
CONFIG += console
CONFIG -= app_bundle

QMAKE_LINK = gcc

SOURCES += \
    main.c

include(../scanner_signatures/scanner_signatures.pri)
