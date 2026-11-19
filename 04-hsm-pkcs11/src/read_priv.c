/* [H1] PKCS#11 API 로 개인키 값을 직접 요청한다.
 * 빌드: gcc -I/usr/include/p11-kit-1 read_priv.c -ldl -o read_priv
 * 실행: ./read_priv /usr/lib/softhsm/libsofthsm2.so 1234
 * 스캐폴드(로드/로그인/키 찾기)는 Claude, TODO 부분은 직접 타이핑(규칙 5).
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <p11-kit/pkcs11.h>

#define CHECK(rv, what) do { if ((rv) != CKR_OK) { \
    printf("%s 실패: rv=0x%lx\n", what, (unsigned long)(rv)); return 1; } } while (0)

int main(int argc, char **argv)
{
    if (argc < 3) { printf("usage: %s <module.so> <pin>\n", argv[0]); return 1; }

    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { printf("dlopen: %s\n", dlerror()); return 1; }
    CK_C_GetFunctionList getfl = (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR p;
    CHECK(getfl(&p), "C_GetFunctionList");
    CHECK(p->C_Initialize(NULL), "C_Initialize");

    CK_SLOT_ID slots[8]; CK_ULONG ns = 8;
    CHECK(p->C_GetSlotList(CK_TRUE, slots, &ns), "C_GetSlotList");
    CK_SESSION_HANDLE s;
    CHECK(p->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s), "C_OpenSession");
    CHECK(p->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)argv[2], strlen(argv[2])), "C_Login");

    /* label "fitkey" 인 개인키 핸들 찾기 */
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_LABEL, "fitkey", 6 },
    };
    CK_OBJECT_HANDLE key; CK_ULONG n = 0;
    CHECK(p->C_FindObjectsInit(s, find, 2), "C_FindObjectsInit");
    CHECK(p->C_FindObjects(s, &key, 1, &n), "C_FindObjects");
    p->C_FindObjectsFinal(s);
    if (n == 0) { printf("키 없음\n"); return 1; }
    printf("개인키 핸들 = %lu\n", (unsigned long)key);


    /* ===== TODO (직접 타이핑) =====
     * 1) 버퍼 하나 (unsigned char buf[512]) 를 잡고
     * 2) CK_ATTRIBUTE 템플릿 1칸: 타입 CKA_PRIVATE_EXPONENT, 값 buf, 길이 sizeof(buf)
     * 3) p->C_GetAttributeValue(s, key, 템플릿, 1) 을 부르고
     * 4) 반환값 rv 와 템플릿의 ulValueLen 을 printf 로 찍는다 (%lx)
     *    (CKR_ATTRIBUTE_SENSITIVE = 0x11, CK_UNAVAILABLE_INFORMATION = (CK_ULONG)-1)
     */
    unsigned char buf[512];
    CK_ATTRIBUTE get[] = {
	    { CKA_PRIVATE_EXPONENT, buf, sizeof(buf) },

    };

    CK_RV rv = p->C_GetAttributeValue(s, key, get, 1);
    printf("%lx,%lx\n", rv, get[0].ulValueLen);

    p->C_Logout(s);
    p->C_CloseSession(s);
    p->C_Finalize(NULL);
    return 0;
}
