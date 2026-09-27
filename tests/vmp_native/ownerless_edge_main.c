/* Execute both independent native oracles in the exact ownerless IDA input. */
#define main edge_dataflow_main
#include "dataflow_main.c"
#undef main
#define main edge_ownerless_main
#include "ownerless_dataflow.c"
#undef main

int main(void)
{
    const int result = edge_dataflow_main();
    return result == 0 ? edge_ownerless_main() : result;
}
