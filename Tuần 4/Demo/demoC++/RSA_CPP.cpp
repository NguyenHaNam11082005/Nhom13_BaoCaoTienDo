/*
 * RSA Digital Signature Demo - C++ / Win32 / OpenSSL
 * Build (x64 Developer Command Prompt in Visual Studio):
 *   cl /EHsc /W3 RSA_Demo.cpp /I"C:\OpenSSL-Win64\include" ^
 *      /link /LIBPATH:"C:\OpenSSL-Win64\lib\VC\x64\MT" ^
 *      libssl.lib libcrypto.lib Ws2_32.lib Crypt32.lib user32.lib ^
 *      comdlg32.lib gdi32.lib comctl32.lib /SUBSYSTEM:WINDOWS
 *
 * If OpenSSL is installed to a different path, adjust /I and /LIBPATH above.
 */

//#define UNICODE
//#define _UNICODE
#define WIN32_LEAN_AND_MEAN






#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <windowsx.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

 /* ==================== Control IDs ==================== */
#define ID_BTN_AUTO_KEY     101
#define ID_BTN_MANUAL_KEY   102
#define ID_BTN_RESET_KEY    103
#define ID_BTN_CHOOSE_SIGN  110
#define ID_BTN_SIGN         111
#define ID_BTN_SAVE_SIG     112
#define ID_BTN_TRANSFER     113
#define ID_BTN_RESET_SIGN   114
#define ID_BTN_CHOOSE_DOC   120
#define ID_BTN_CHOOSE_SIG   121
#define ID_BTN_VERIFY       122
#define ID_BTN_EDIT_SIG     123
#define ID_BTN_RESET_VERIFY 124

#define ID_EDIT_P           201
#define ID_EDIT_Q           202
#define ID_EDIT_E           203
#define ID_EDIT_N           204
#define ID_EDIT_D           205
#define ID_EDIT_HASH_SIGN   206
#define ID_EDIT_SIGN_CONTENT 207
#define ID_EDIT_SIGNATURE   208
#define ID_EDIT_VERIFY_CONTENT 209
#define ID_EDIT_VERIFY_SIG  210
#define ID_COMBO_HASH       211

#define ID_LBL_RESULT       301

/* ==================== Global state ==================== */
static HWND g_hwnd = nullptr;

// Key fields (stored as PEM strings for simplicity in demo)
static EVP_PKEY* g_pkey = nullptr;   // holds current key pair

// We also keep the OpenSSL BIGNUMs for manual display
static std::string g_p_str, g_q_str, g_e_str, g_n_str, g_d_str;

/* ==================== Utility ==================== */
static std::string WStrToStr(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len - 1, '\0');
    //WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), len, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], len, nullptr, nullptr);
    return s;
}

static std::wstring StrToWStr(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len - 1, L'\0');
    //MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

static std::string GetSSLError()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

static void SetEditText(int id, const std::wstring& text)
{
    SetDlgItemTextW(g_hwnd, id, text.c_str());
}

static std::wstring GetEditText(int id)
{
    wchar_t buf[65536] = {};
    GetDlgItemTextW(g_hwnd, id, buf, (int)(sizeof(buf) / sizeof(buf[0])));
    return buf;
}

static std::string BigNumToStr(const BIGNUM* bn)
{
    char* hex = BN_bn2hex(bn);
    std::string s = hex ? hex : "(null)";
    OPENSSL_free(hex);
    return s;
}

static std::string BytesToHex(const unsigned char* data, size_t len)
{
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

static std::string BytesToBase64(const unsigned char* data, size_t len)
{
    // Simple base64 encoding
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        unsigned char a = data[i];
        unsigned char b = (i + 1 < len) ? data[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? data[i + 2] : 0;
        out += b64[a >> 2];
        out += b64[((a & 3) << 4) | (b >> 4)];
        out += (i + 1 < len) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=';
        out += (i + 2 < len) ? b64[c & 0x3f] : '=';
    }
    return out;
}

static std::vector<unsigned char> Base64ToBytes(const std::string& b64str)
{
    // Uses OpenSSL BIO for decoding
    BIO* bio = BIO_new_mem_buf(b64str.data(), (int)b64str.size());
    BIO* b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64bio, bio);

    std::vector<unsigned char> buf(b64str.size());
    int decoded = BIO_read(bio, buf.data(), (int)buf.size());
    BIO_free_all(bio);
    if (decoded > 0) buf.resize(decoded);
    else buf.clear();
    return buf;
}

/* ==================== File utilities ==================== */
static bool OpenFileDlg(HWND hwnd, std::wstring& outPath,
    const wchar_t* filter = L"All files\0*.*\0Text files\0*.txt\0")
{
    wchar_t buf[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        outPath = buf;
        return true;
    }
    return false;
}

static bool SaveFileDlg(HWND hwnd, std::wstring& outPath,
    const wchar_t* filter = L"Signature files\0*.sig\0Text files\0*.txt\0All files\0*.*\0",
    const wchar_t* defExt = L"sig")
{
    wchar_t buf[MAX_PATH] = {};
    /*SAVEFILENAMEW sfn = {};*/
    OPENFILENAMEW sfn = {};
    sfn.lStructSize = sizeof(sfn);
    sfn.hwndOwner = hwnd;
    sfn.lpstrFilter = filter;
    sfn.lpstrFile = buf;
    sfn.nMaxFile = MAX_PATH;
    sfn.lpstrDefExt = defExt;
    sfn.Flags = OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameW(&sfn)) {
        outPath = buf;
        return true;
    }
    return false;
}

static std::string ReadFileFull(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

static bool WriteFileFull(const std::wstring& path, const std::string& data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(data.data(), data.size());
    return true;
}

/* ==================== RSA Key logic ==================== */

static void FreeCurrentKey()
{
    if (g_pkey) { EVP_PKEY_free(g_pkey); g_pkey = nullptr; }
    g_p_str = g_q_str = g_e_str = g_n_str = g_d_str = "";
}

// Display key components in the UI
static void DisplayKeyParams()
{
    SetEditText(ID_EDIT_P, StrToWStr(g_p_str));
    SetEditText(ID_EDIT_Q, StrToWStr(g_q_str));
    SetEditText(ID_EDIT_E, StrToWStr(g_e_str));
    SetEditText(ID_EDIT_N, StrToWStr(g_n_str));
    SetEditText(ID_EDIT_D, StrToWStr(g_d_str));
}

// Extract and store BIGNUM fields from an RSA key
static bool ExtractRSAParams(EVP_PKEY* pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x
    BIGNUM* n = nullptr, * e = nullptr, * d = nullptr;
    BIGNUM* p = nullptr, * q = nullptr;
    EVP_PKEY_get_bn_param(pkey, "n", &n);
    EVP_PKEY_get_bn_param(pkey, "e", &e);
    EVP_PKEY_get_bn_param(pkey, "d", &d);
    /*EVP_PKEY_get_bn_param(pkey, "p", &p);
    EVP_PKEY_get_bn_param(pkey, "q", &q);*/
    EVP_PKEY_get_bn_param(pkey, "rsa-factor1", &p);
    EVP_PKEY_get_bn_param(pkey, "rsa-factor2", &q);


    if (!n || !e || !d || !p || !q) {
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
        return false;
    }
    g_n_str = BigNumToStr(n);
    g_e_str = BigNumToStr(e);
    g_d_str = BigNumToStr(d);
    g_p_str = BigNumToStr(p);
    g_q_str = BigNumToStr(q);
    BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
#else
    // OpenSSL 1.x
    const RSA* rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) return false;
    const BIGNUM* n, * e, * d, * p, * q;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    g_n_str = BigNumToStr(n);
    g_e_str = BigNumToStr(e);
    g_d_str = BigNumToStr(d);
    g_p_str = BigNumToStr(p);
    g_q_str = BigNumToStr(q);
#endif
    return true;
}

// Auto key generation: 2048-bit RSA
static void GenerateAutoKey()
{
    FreeCurrentKey();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) { MessageBoxW(g_hwnd, L"Cannot create key context.", L"Lỗi", MB_ICONERROR); return; }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &g_pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        MessageBoxW(g_hwnd, L"Tạo khóa thất bại.", L"Lỗi", MB_ICONERROR);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    ExtractRSAParams(g_pkey);
    DisplayKeyParams();
    MessageBoxW(g_hwnd, L"Đã tạo cặp khóa RSA 2048-bit thành công.", L"Thông báo", MB_ICONINFORMATION);
}

// Manual key from p, q, e (parse hex or decimal from textboxes)
static void CreateManualKey()
{
    // For demo: read p, q, e as hex strings and build RSA key
    std::string ps = WStrToStr(GetEditText(ID_EDIT_P));
    std::string qs = WStrToStr(GetEditText(ID_EDIT_Q));
    std::string es = WStrToStr(GetEditText(ID_EDIT_E));

    if (ps.empty() || qs.empty() || es.empty()) {
        MessageBoxW(g_hwnd, L"Vui lòng nhập đủ p, q, e (dạng hex, ví dụ: 3D).", L"Lỗi", MB_ICONERROR);
        return;
    }

    BIGNUM* bnp = nullptr, * bnq = nullptr, * bne = nullptr;
    // Try hex parse first, then decimal
    auto parse = [](const std::string& s, BIGNUM** out) -> bool {
        *out = nullptr;
        if (BN_hex2bn(out, s.c_str()) > 0) return true;
        return BN_dec2bn(out, s.c_str()) > 0;
        };
    if (!parse(ps, &bnp) || !parse(qs, &bnq) || !parse(es, &bne)) {
        BN_free(bnp); BN_free(bnq); BN_free(bne);
        MessageBoxW(g_hwnd, L"p, q hoặc e không hợp lệ.", L"Lỗi", MB_ICONERROR);
        return;
    }

    // Miller-Rabin primality check (OpenSSL built-in, 64 rounds)
    BN_CTX* bnctx = BN_CTX_new();
    int p_prime = BN_check_prime(bnp, bnctx, nullptr);
    int q_prime = BN_check_prime(bnq, bnctx, nullptr);
    BN_CTX_free(bnctx);

    if (p_prime != 1) {
        BN_free(bnp); BN_free(bnq); BN_free(bne);
        MessageBoxW(g_hwnd, L"p không phải số nguyên tố.", L"Lỗi", MB_ICONERROR);
        return;
    }
    if (q_prime != 1) {
        BN_free(bnp); BN_free(bnq); BN_free(bne);
        MessageBoxW(g_hwnd, L"q không phải số nguyên tố.", L"Lỗi", MB_ICONERROR);
        return;
    }
    if (BN_cmp(bnp, bnq) == 0) {
        BN_free(bnp); BN_free(bnq); BN_free(bne);
        MessageBoxW(g_hwnd, L"p và q phải khác nhau.", L"Lỗi", MB_ICONERROR);
        return;
    }

    // Compute n, phi, d
    BN_CTX* ctx2 = BN_CTX_new();
    BIGNUM* bnn = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* p1 = BN_new();
    BIGNUM* q1 = BN_new();
    BIGNUM* bnd = BN_new();
    BIGNUM* gcd = BN_new();

    BN_mul(bnn, bnp, bnq, ctx2);
    BN_sub(p1, bnp, BN_value_one());
    BN_sub(q1, bnq, BN_value_one());
    BN_mul(phi, p1, q1, ctx2);
    BN_gcd(gcd, bne, phi, ctx2);

    if (BN_cmp(gcd, BN_value_one()) != 0) {
        BN_free(bnp); BN_free(bnq); BN_free(bne);
        BN_free(bnn); BN_free(phi); BN_free(p1); BN_free(q1); BN_free(bnd); BN_free(gcd);
        BN_CTX_free(ctx2);
        MessageBoxW(g_hwnd, L"gcd(e, phi(n)) ≠ 1. Chọn e khác.", L"Lỗi", MB_ICONERROR);
        return;
    }

    BN_mod_inverse(bnd, bne, phi, ctx2);

    // Build EVP_PKEY from components
    FreeCurrentKey(); // Gọi xóa khóa cũ trước

    // Rồi mới gán chuỗi mới để in ra UI
    g_p_str = BigNumToStr(bnp);
    g_q_str = BigNumToStr(bnq);
    g_e_str = BigNumToStr(bne);
    g_n_str = BigNumToStr(bnn);
    g_d_str = BigNumToStr(bnd);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, "n", bnn);
    OSSL_PARAM_BLD_push_BN(bld, "e", bne);
    OSSL_PARAM_BLD_push_BN(bld, "d", bnd);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-factor1", bnp);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-factor2", bnq);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY_fromdata_init(pkctx);
    EVP_PKEY_fromdata(pkctx, &g_pkey, EVP_PKEY_KEYPAIR, params);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pkctx);
#else
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, BN_dup(bnn), BN_dup(bne), BN_dup(bnd));
    RSA_set0_factors(rsa, BN_dup(bnp), BN_dup(bnq));
    g_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(g_pkey, rsa);
#endif

    BN_free(bnp); BN_free(bnq); BN_free(bne);
    BN_free(bnn); BN_free(phi); BN_free(p1); BN_free(q1); BN_free(bnd); BN_free(gcd);
    BN_CTX_free(ctx2);

    DisplayKeyParams();
    MessageBoxW(g_hwnd, L"Đã tạo khóa thủ công thành công.", L"Thông báo", MB_ICONINFORMATION);
}

/* ==================== Hash ==================== */
static std::vector<unsigned char> ComputeHash(
    const unsigned char* data, size_t len, int hashIdx)
{
    // hashIdx: 0=MD5, 1=SHA1, 2=SHA256
    const EVP_MD* md = (hashIdx == 0) ? EVP_md5() :
        (hashIdx == 1) ? EVP_sha1() : EVP_sha256();
    unsigned int outLen = 0;
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest.data(), &outLen);
    EVP_MD_CTX_free(ctx);
    digest.resize(outLen);
    return digest;
}

/* ==================== Sign ==================== */
static void SignDocument()
{
    if (!g_pkey) {
        MessageBoxW(g_hwnd, L"Chưa có khóa. Hãy tạo hoặc nhập khóa trước.", L"Lỗi", MB_ICONERROR);
        return;
    }
    int hashIdx = (int)SendDlgItemMessageW(g_hwnd, ID_COMBO_HASH, CB_GETCURSEL, 0, 0);
    if (hashIdx < 0) {
        MessageBoxW(g_hwnd, L"Chưa chọn thuật toán băm.", L"Lỗi", MB_ICONERROR);
        return;
    }
    std::string content = WStrToStr(GetEditText(ID_EDIT_SIGN_CONTENT));
    if (content.empty()) {
        MessageBoxW(g_hwnd, L"Nội dung văn bản ký trống.", L"Lỗi", MB_ICONERROR);
        return;
    }

    const EVP_MD* md = (hashIdx == 0) ? EVP_md5() :
        (hashIdx == 1) ? EVP_sha1() : EVP_sha256();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, md, nullptr, g_pkey);
    EVP_DigestSignUpdate(ctx, content.data(), content.size());

    size_t sigLen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sigLen);
    std::vector<unsigned char> sig(sigLen);
    EVP_DigestSignFinal(ctx, sig.data(), &sigLen);
    EVP_MD_CTX_free(ctx);
    sig.resize(sigLen);

    // Display hash for visualization
    auto hashVal = ComputeHash(
        reinterpret_cast<const unsigned char*>(content.data()), content.size(), hashIdx);
    std::string hashHex = BytesToHex(hashVal.data(), hashVal.size());

    // Encode signature as Base64 for display/storage
    std::string sigB64 = BytesToBase64(sig.data(), sig.size());
    SetEditText(ID_EDIT_SIGNATURE, StrToWStr(sigB64));
    SetEditText(ID_EDIT_HASH_SIGN, StrToWStr(hashHex));

    MessageBoxW(g_hwnd, L"Đã tạo chữ ký số thành công.", L"Thông báo", MB_ICONINFORMATION);
}

/* ==================== Verify ==================== */
static void VerifySignature()
{
    if (!g_pkey) {
        MessageBoxW(g_hwnd, L"Chưa có khóa.", L"Lỗi", MB_ICONERROR);
        return;
    }
    int hashIdx = (int)SendDlgItemMessageW(g_hwnd, ID_COMBO_HASH, CB_GETCURSEL, 0, 0);
    if (hashIdx < 0) {
        MessageBoxW(g_hwnd, L"Chưa chọn thuật toán băm.", L"Lỗi", MB_ICONERROR);
        return;
    }
    std::string content = WStrToStr(GetEditText(ID_EDIT_VERIFY_CONTENT));
    std::string sigB64 = WStrToStr(GetEditText(ID_EDIT_VERIFY_SIG));
    if (content.empty() || sigB64.empty()) {
        MessageBoxW(g_hwnd, L"Thiếu văn bản hoặc chữ ký.", L"Lỗi", MB_ICONERROR);
        return;
    }

    auto sig = Base64ToBytes(sigB64);
    if (sig.empty()) {
        MessageBoxW(g_hwnd, L"Chữ ký không đúng định dạng Base64.", L"Lỗi", MB_ICONERROR);
        return;
    }

    const EVP_MD* md = (hashIdx == 0) ? EVP_md5() :
        (hashIdx == 1) ? EVP_sha1() : EVP_sha256();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, g_pkey);
    EVP_DigestVerifyUpdate(ctx, content.data(), content.size());
    int result = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());
    EVP_MD_CTX_free(ctx);

    HWND hLabel = GetDlgItem(g_hwnd, ID_LBL_RESULT);
    if (result == 1) {
        SetWindowTextW(hLabel,
            L"✔ Chữ ký hợp lệ – Văn bản đảm bảo tính toàn vẹn và xác thực");
        SetWindowLongPtrW(hLabel, GWLP_USERDATA, RGB(0, 128, 0));
    }
    else {
        SetWindowTextW(hLabel,
            L"✘ Chữ ký KHÔNG hợp lệ – Văn bản đã bị sửa đổi hoặc khóa không chính xác");
        SetWindowLongPtrW(hLabel, GWLP_USERDATA, RGB(200, 0, 0));
    }
    InvalidateRect(hLabel, nullptr, TRUE);
}

/* ==================== Transfer ==================== */
static void TransferData()
{
    std::wstring content = GetEditText(ID_EDIT_SIGN_CONTENT);
    std::wstring sig = GetEditText(ID_EDIT_SIGNATURE);
    if (sig.empty()) {
        MessageBoxW(g_hwnd, L"Chưa có chữ ký để chuyển tiếp.", L"Lỗi", MB_ICONERROR);
        return;
    }
    SetEditText(ID_EDIT_VERIFY_CONTENT, content);
    SetEditText(ID_EDIT_VERIFY_SIG, sig);
    MessageBoxW(g_hwnd, L"Đã chuyển tiếp dữ liệu sang khu vực kiểm tra.", L"Thông báo", MB_ICONINFORMATION);
}

/* ==================== Edit signature (tamper demo) ==================== */
//static void EditSignature()
//{
//    std::wstring sig = GetEditText(ID_EDIT_VERIFY_SIG);
//    if (sig.empty()) {
//        MessageBoxW(g_hwnd, L"Không có chữ ký để sửa.", L"Lỗi", MB_ICONERROR);
//        return;
//    }
//    // Flip last alphanumeric char
//    for (int i = (int)sig.size() - 1; i >= 0; i--) {
//        if (isalnum((unsigned char)sig[i])) {
//            sig[i] = (sig[i] == L'z') ? L'A' : sig[i] + 1;
//            break;
//        }
//    }
//    SetEditText(ID_EDIT_VERIFY_SIG, sig);
//    MessageBoxW(g_hwnd, L"Đã giả mạo chữ ký. Bấm Kiểm Tra để xem kết quả.", L"Thông báo", MB_ICONINFORMATION);
//}
static void EditSignature()
{
    std::wstring sig = GetEditText(ID_EDIT_VERIFY_SIG);
    if (sig.empty()) {
        MessageBoxW(g_hwnd, L"Không có chữ ký để sửa.", L"Lỗi", MB_ICONERROR);
        return;
    }

    // Đổi ký tự ĐẦU TIÊN thay vì ký tự cuối cùng để chắc chắn phá hỏng dữ liệu giải mã
    for (int i = 0; i < (int)sig.size(); i++) {
        if (isalnum((unsigned char)sig[i])) {
            sig[i] = (sig[i] == L'z') ? L'A' : sig[i] + 1;
            break;
        }
    }

    SetEditText(ID_EDIT_VERIFY_SIG, sig);
    MessageBoxW(g_hwnd, L"Đã giả mạo chữ ký. Bấm Kiểm Tra để xem kết quả.", L"Thông báo", MB_ICONINFORMATION);
}
/* ==================== Save signature ==================== */
static void SaveSignature()
{
    std::wstring sig = GetEditText(ID_EDIT_SIGNATURE);
    if (sig.empty()) {
        MessageBoxW(g_hwnd, L"Chưa có chữ ký để lưu.", L"Lỗi", MB_ICONWARNING);
        return;
    }
    std::wstring path;
    if (SaveFileDlg(g_hwnd, path)) {
        WriteFileFull(path, WStrToStr(sig));
        MessageBoxW(g_hwnd, L"Đã lưu file chữ ký.", L"Thông báo", MB_ICONINFORMATION);
    }
}

/* ==================== UI Layout ==================== */
static HWND MakeGroup(HWND parent, const wchar_t* title, int x, int y, int w, int h)
{
    return CreateWindowW(L"BUTTON", title,
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        x, y, w, h, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
}

static HWND MakeLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h)
{
    return CreateWindowW(L"STATIC", text,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        x, y, w, h, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
}

static HWND MakeEdit(HWND parent, UINT id, int x, int y, int w, int h,
    bool multiline = false, bool readOnly = false)
{
    DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    if (multiline) style |= ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL;
    if (readOnly) style |= ES_READONLY;
    return CreateWindowW(L"EDIT", L"",
        style, x, y, w, h, parent, (HMENU)(UINT_PTR)id,
        GetModuleHandleW(nullptr), nullptr);
}

static HWND MakeButton(HWND parent, const wchar_t* text, UINT id, int x, int y, int w, int h)
{
    return CreateWindowW(L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, w, h, parent, (HMENU)(UINT_PTR)id,
        GetModuleHandleW(nullptr), nullptr);
}

static void BuildUI(HWND hwnd)
{
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    auto SetFont = [&](HWND h) { SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE); };

    // ---- KEY GROUP ----
    HWND grpKey = MakeGroup(hwnd, L" Tạo Khóa ", 10, 10, 280, 540);
    SetFont(grpKey);

    SetFont(MakeLabel(hwnd, L"Khóa công khai (e, n)", 20, 32, 200, 18));
    SetFont(MakeLabel(hwnd, L"Số nguyên tố p =", 20, 52, 150, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_P, 20, 70, 255, 22));
    SetFont(MakeLabel(hwnd, L"Số nguyên tố q =", 20, 96, 150, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_Q, 20, 114, 255, 22));
    SetFont(MakeLabel(hwnd, L"Số e (1 < e < phi(n)) =", 20, 140, 200, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_E, 20, 158, 255, 22));
    SetFont(MakeLabel(hwnd, L"n = p × q:", 20, 184, 150, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_N, 20, 202, 255, 22));
    SetFont(MakeLabel(hwnd, L"Khóa bí mật (d, n)", 20, 234, 200, 18));
    SetFont(MakeLabel(hwnd, L"d = e⁻¹ mod phi(n) =", 20, 254, 200, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_D, 20, 272, 255, 22));

    SetFont(MakeButton(hwnd, L"Tạo Khóa Ngẫu Nhiên", ID_BTN_AUTO_KEY, 60, 312, 190, 30));
    SetFont(MakeButton(hwnd, L"Tạo Khóa Thủ Công", ID_BTN_MANUAL_KEY, 60, 350, 190, 30));
    SetFont(MakeButton(hwnd, L"Reset Tất Cả", ID_BTN_RESET_KEY, 60, 388, 190, 30));

    // ---- SIGN GROUP ----
    HWND grpSign = MakeGroup(hwnd, L" Tạo Chữ Ký ", 302, 10, 450, 540);
    SetFont(grpSign);

    SetFont(MakeLabel(hwnd, L"Văn Bản Ký", 312, 32, 200, 18));
    SetFont(MakeButton(hwnd, L"Chọn File", ID_BTN_CHOOSE_SIGN, 672, 28, 68, 24));
    SetFont(MakeEdit(hwnd, ID_EDIT_SIGN_CONTENT, 312, 52, 428, 90, true));

    SetFont(MakeLabel(hwnd, L"Hàm Băm", 312, 152, 80, 18));
    HWND hCombo = CreateWindowW(L"COMBOBOX", nullptr,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        312, 170, 140, 100, hwnd, (HMENU)ID_COMBO_HASH,
        GetModuleHandleW(nullptr), nullptr);
    SetFont(hCombo);
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"MD5");
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA-1");
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA-256");

    SetFont(MakeLabel(hwnd, L"Giá Trị Hash (hex):", 460, 152, 160, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_HASH_SIGN, 460, 170, 278, 22, false, true));

    SetFont(MakeButton(hwnd, L"Tiến Hành Ký Văn Bản", ID_BTN_SIGN, 396, 202, 180, 30));

    SetFont(MakeLabel(hwnd, L"Chữ Ký Số (Base64)", 312, 244, 200, 18));
    SetFont(MakeEdit(hwnd, ID_EDIT_SIGNATURE, 312, 262, 428, 110, true));

    SetFont(MakeButton(hwnd, L"Chuyển Tiếp Dữ Liệu", ID_BTN_TRANSFER, 396, 382, 175, 28));
    SetFont(MakeButton(hwnd, L"Lưu File Chữ Ký", ID_BTN_SAVE_SIG, 396, 416, 175, 28));
    SetFont(MakeButton(hwnd, L"Reset", ID_BTN_RESET_SIGN, 396, 450, 175, 28));

    // ---- VERIFY GROUP ----
    HWND grpVfy = MakeGroup(hwnd, L" Kiểm Tra Chữ Ký ", 764, 10, 510, 540);
    SetFont(grpVfy);

    SetFont(MakeLabel(hwnd, L"Văn Bản Cần Kiểm Tra", 774, 32, 200, 18));
    SetFont(MakeButton(hwnd, L"File VB", ID_BTN_CHOOSE_DOC, 1180, 28, 80, 24));
    SetFont(MakeEdit(hwnd, ID_EDIT_VERIFY_CONTENT, 774, 52, 488, 110, true));

    SetFont(MakeLabel(hwnd, L"Chữ Ký Cần Kiểm Tra", 774, 174, 200, 18));
    SetFont(MakeButton(hwnd, L"File CK", ID_BTN_CHOOSE_SIG, 1180, 170, 80, 24));
    SetFont(MakeEdit(hwnd, ID_EDIT_VERIFY_SIG, 774, 192, 488, 110, true));

    SetFont(MakeButton(hwnd, L"Tiến Hành Kiểm Tra Chữ Ký", ID_BTN_VERIFY, 854, 316, 220, 30));
    SetFont(MakeButton(hwnd, L"Giả Mạo Chữ Ký (Demo)", ID_BTN_EDIT_SIG, 854, 354, 220, 30));
    SetFont(MakeButton(hwnd, L"Reset", ID_BTN_RESET_VERIFY, 854, 392, 220, 28));

    // Result label (colored)
    HWND hResult = CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        774, 434, 488, 70,
        hwnd, (HMENU)ID_LBL_RESULT,
        GetModuleHandleW(nullptr), nullptr);
    SetFont(hResult);
}

/* ==================== Window proc ==================== */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
        g_hwnd = hwnd;
        BuildUI(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case ID_BTN_AUTO_KEY:    GenerateAutoKey();   break;
        case ID_BTN_MANUAL_KEY:  CreateManualKey();   break;
        case ID_BTN_RESET_KEY:
            FreeCurrentKey();
            SetEditText(ID_EDIT_P, L""); SetEditText(ID_EDIT_Q, L"");
            SetEditText(ID_EDIT_E, L""); SetEditText(ID_EDIT_N, L"");
            SetEditText(ID_EDIT_D, L"");
            SetEditText(ID_EDIT_SIGN_CONTENT, L"");
            SetEditText(ID_EDIT_SIGNATURE, L"");
            SetEditText(ID_EDIT_VERIFY_CONTENT, L"");
            SetEditText(ID_EDIT_VERIFY_SIG, L"");
            SetEditText(ID_EDIT_HASH_SIGN, L"");
            SetWindowTextW(GetDlgItem(hwnd, ID_LBL_RESULT), L"");
            SendDlgItemMessageW(hwnd, ID_COMBO_HASH, CB_SETCURSEL, (WPARAM)-1, 0);
            break;

        case ID_BTN_CHOOSE_SIGN: {
            std::wstring path;
            if (OpenFileDlg(hwnd, path)) {
                std::string txt = ReadFileFull(path);
                SetEditText(ID_EDIT_SIGN_CONTENT, StrToWStr(txt));
            }
            break;
        }
        case ID_BTN_SIGN:          SignDocument();     break;
        case ID_BTN_SAVE_SIG:      SaveSignature();    break;
        case ID_BTN_TRANSFER:      TransferData();     break;
        case ID_BTN_RESET_SIGN:
            SetEditText(ID_EDIT_SIGN_CONTENT, L"");
            SetEditText(ID_EDIT_SIGNATURE, L"");
            SetEditText(ID_EDIT_HASH_SIGN, L"");
            SendDlgItemMessageW(hwnd, ID_COMBO_HASH, CB_SETCURSEL, (WPARAM)-1, 0);
            break;

        case ID_BTN_CHOOSE_DOC: {
            std::wstring path;
            if (OpenFileDlg(hwnd, path)) {
                std::string txt = ReadFileFull(path);
                SetEditText(ID_EDIT_VERIFY_CONTENT, StrToWStr(txt));
            }
            break;
        }
        case ID_BTN_CHOOSE_SIG: {
            std::wstring path;
            if (OpenFileDlg(hwnd, path, L"Signature files\0*.sig\0Text files\0*.txt\0All\0*.*\0")) {
                std::string txt = ReadFileFull(path);
                SetEditText(ID_EDIT_VERIFY_SIG, StrToWStr(txt));
            }
            break;
        }
        case ID_BTN_VERIFY:        VerifySignature();  break;
        case ID_BTN_EDIT_SIG:      EditSignature();    break;
        case ID_BTN_RESET_VERIFY:
            SetEditText(ID_EDIT_VERIFY_CONTENT, L"");
            SetEditText(ID_EDIT_VERIFY_SIG, L"");
            SetWindowTextW(GetDlgItem(hwnd, ID_LBL_RESULT), L"");
            InvalidateRect(GetDlgItem(hwnd, ID_LBL_RESULT), nullptr, TRUE);
            break;
        }
        return 0;

   /* case WM_CTLCOLORSTATIC: {
        HWND hCtrl = (HWND)lp;
        if (GetDlgCtrlID(hCtrl) == ID_LBL_RESULT) {
            HDC hdc = (HDC)wp;
            COLORREF clr = (COLORREF)GetWindowLongPtrW(hCtrl, GWLP_USERDATA);
            SetTextColor(hdc, clr ? clr : GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor(hdc, GetSysColor(COLOR_BTNFACE));
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }*/
    case WM_CTLCOLORSTATIC: {
        HWND hCtrl = (HWND)lp;
        if (GetDlgCtrlID(hCtrl) == ID_LBL_RESULT) {
            HDC hdc = (HDC)wp;
            COLORREF clr = (COLORREF)GetWindowLongPtrW(hCtrl, GWLP_USERDATA);
            SetTextColor(hdc, clr ? clr : GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor(hdc, GetSysColor(COLOR_BTNFACE));
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    case WM_DESTROY:
        FreeCurrentKey();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ==================== WinMain ==================== */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"RSADemoWnd";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0,
        L"RSADemoWnd", L"Chữ Ký Số RSA – C++ / OpenSSL",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1300, 620,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
