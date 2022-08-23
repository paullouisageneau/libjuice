## Fuzzer

### Export Symbols
```
export CC=clang
export CXX=clang++
export CFLAGS=-fsanitize=fuzzer-no-link,address
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
export LDFLAGS=-fsanitize=address
```

### Build
```
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DFUZZER=ON -DCMAKE_C_COMPILER=$CC \
-DCMAKE_C_FLAGS=$CFLAGS -DCMAKE_EXE_LINKER_FLAGS=$CFLAGS \
-DLIB_FUZZING_ENGINE=$LIB_FUZZING_ENGINE \
../
```

### Run
```
$ mkdir coverage
$ ./fuzzer coverage/ ../fuzzer/input/
```
