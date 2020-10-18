```C
ADDRESS array_address[500];
uint32 count;

if (AOBScan(&process, "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF", SCANNER_EXECUTE_READ, 500, array_address, &count))
{
    printf("found %ld\n", count);

    for (uint32 i = 0; i < count; i++) {
        print_address(array_address[i]);
    }
}
```
