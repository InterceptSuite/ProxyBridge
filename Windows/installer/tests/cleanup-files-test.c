#define wmain bootstrap_test_main
#include "bootstrap-path-test.c"
#undef wmain
int wmain(int argc, WCHAR **argv)
{
    if (argc != 3) return 1;
    testDirectory = argv[1];
    const BYTE hash[32] = {0x56,0x4d,0x9b,0x99,0xaa,0x9f,0x88,0x00,0x81,0x56,0x55,0xfb,0x61,0x9f,0x53,0x3b,
        0xc0,0x72,0xe0,0x47,0x7f,0x7f,0x04,0xe9,0xf7,0x70,0xb1,0x32,0x6b,0xd7,0xb1,0xee};
    PB_VERIFIED_PAYLOAD source = {0}, guard = {0}; HANDLE root = NULL;
    DWORD error = pb_payload_open(argv[2], hash, 4, 65537, &source);
    if (!error) error = pb_stage_root_open(&guard, &root);
    GUID transaction = {0}; transaction.Data1 = 123;
    WCHAR target[MAX_PATH] = {0};
    if (!error) error = pb_stage_payload(root, &transaction, &source, hash, target);
    pb_payload_close(&source);
    if (!error && pb_stage_cleanup_files(root, argv[2], hash, 4, 65537) != ERROR_INVALID_NAME) error = ERROR_GEN_FAILURE;
    if (!error) error = pb_stage_cleanup_files(root, target, hash, 4, 65537);
    if (!error) error = pb_stage_cleanup_files(root, target, hash, 4, 65537);
    PB_VERIFIED_PAYLOAD remaining = {0};
    if (!error) error = pb_payload_open_remaining(target, hash, 4, 65537, &remaining);
    if (!error) for (unsigned i = 0; i < PB_PAYLOAD_FILES; ++i) if (remaining.files[i]) error = ERROR_GEN_FAILURE;
    if (!error && !remaining.files[PB_PAYLOAD_FILES]) error = ERROR_GEN_FAILURE;
    pb_payload_close(&remaining); pb_payload_close(&guard);
    printf("Protected cleanup and retry result: %lu; manifest retained.\n", error);
    return error ? 1 : 0;
}
