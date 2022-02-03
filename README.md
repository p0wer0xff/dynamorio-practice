# DynamoRIO Practice

## Building

Run the `Build DynamoRIO` task then the `Build` task in VSCode.

## Running

In the root directory run:

```bash
build_dr/bin64/drrun -c build/libcount_bb.so -- build/sample_hello_world
```

`libcount_bb.so` can be replaced by another client and `sample_hello_world` can be replaced by another sample program.

## Clients

### count_bb

Prints the number of unique basic blocks that are executed.
