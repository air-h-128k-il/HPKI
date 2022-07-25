/*---------------------------------------------------------------------*/
/* FILE NAME  :  HPKISignSampleCrypto.c                 */
/* VERSION    :  1.0                           */
/* DATE      :  2020/10/29                       */
/*---------------------------------------------------------------------*/


/*=====================================================================*/
/*                             INCLUDE                                 */
/*=====================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <Windows.h>
#include <wincrypt.h>

/*=====================================================================*/
/*                             DEFINITION                              */
/*=====================================================================*/

#define APROVNAME TEXT("HPKI Crypto Service Provider for Authentication")
#define SPROVNAME TEXT("HPKI Crypto Service Provider for Non Repudiation")
#define HASHSIZE_SHA1 (160 / 8)

/*=====================================================================*/
/*              DEFINITIOIN OF PRIVATE FUNCTION               */
/*=====================================================================*/

/* プログラムの実行形式　*/
void PrintUsage() {
  printf("Usage : HPKISignSample <prov_type> <method> <pin>\n");
  printf("prov_type:　auth | sign\n");
  printf("method:　getcert | sign\n");
  printf("pin:　HPKICard PIN\n");
}

/* エラー発生時の処理 */
void printErrorAndExit(const char *f)
{
  DWORD errorcode;
  char errmsg[256];

  errorcode = GetLastError();
  FormatMessageA(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
    FORMAT_MESSAGE_MAX_WIDTH_MASK,
    NULL,
    errorcode,
    MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
    errmsg, sizeof(errmsg) / sizeof(TCHAR),
    NULL);
  printf("%s: 0x%08x (%s).\n", f, errorcode, errmsg);

  exit(EXIT_FAILURE);
}

/* 各データ(証明書データ、署名データ)を16進数表示で標準出力 */
void printHex(const BYTE* data, DWORD len, BOOL limit)
{
  DWORD displen;

  if (limit && len > 256)
    displen = 256;
  else
    displen = len;
  for (DWORD i = 0; i < displen; i++) {
    printf("%02x", *(data + i));
    if (i % 16 == 15 || i == displen - 1)
      printf("\n");
    else
      printf(" ");
  }
  if (displen < len)
    printf("...\n");
}

/*
 * getCert: 利用者証明書取得処理
 * 以下の手順で証明書を取得する。
 * 1. プロバイダハンドル取得
 * 2. RSA鍵ペアのハンドル取得
 * 3. 証明書データ取得
 * 4. 鍵ハンドル破棄
 * 5. プロバイダハンドル解放
 */

void getCert(LPCTSTR pProvName)
{
  HCRYPTPROV hProv;
  HCRYPTKEY  hKey;
  BYTE* certData;
  DWORD certLen;

  /* (1) 暗号プロバイダとコンテナを指定して、プロバイダハンドルを取得する。 */
  if (!CryptAcquireContext(&hProv, NULL, pProvName, PROV_RSA_FULL, 0)) {
    printErrorAndExit("CryptAcquireContext");
  }

  /* (2) コンテナの保持するRSA鍵ペアのハンドルを取得する。 */
  if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
    printErrorAndExit("CryptGetUserKey");
  }

  /* (3) 鍵ハンドルに付随する利用者証明書データのデータ長を取得する。 */
  certLen = 0;
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(1)");
  }

  certData = malloc(certLen);
  if (certData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (4) 鍵ハンドルに付随する利用者証明書データのデータを取得する。 */
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, certData, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(2)");
  }

  printf("Certificate:\n");
  printHex(certData, certLen, FALSE);

  free(certData);

  /* (5) 鍵ハンドルを破棄する。 */
  if (!CryptDestroyKey(hKey)) {
    printErrorAndExit("CryptDestroyKey");
  }

  /* (6) プロバイダハンドルを解放する。 */
  if (!CryptReleaseContext(hProv, 0)) {
    printErrorAndExit("CryptReleaseContext");
  }
}

/*
 * sign: 署名処理
 * 以下の手順で署名を実施する。
 *  1. プロバイダハンドル取得
 *  2. RSA鍵ペアのハンドル取得
 *  3. 証明書データ取得
 *  4. ハッシュオブジェクト生成
 *  5. ハッシュ値設定
 *  6. 署名データ長取得
 *  7. PIN設定
 *  8. 署名データ取得
 *  9. ハッシュオブジェクト破棄
 * 10. 鍵ハンドル破棄
 * 11. プロバイダハンドル解放
 */

void sign(LPCTSTR pProvName, const BYTE *pPinData, DWORD pinLen)
{
  HCRYPTPROV hProv;
  HCRYPTKEY  hKey;
  HCRYPTHASH hHash;
  BYTE* certData;
  DWORD certLen;
  BYTE hashData[256];
  BYTE* sigData;
  DWORD sigLen;

  /* (7) 暗号プロバイダとコンテナを指定して、プロバイダハンドルを取得する。 */
  if (!CryptAcquireContext(&hProv, NULL, pProvName, PROV_RSA_FULL, 0)) {
    printErrorAndExit("CryptAcquireContext");
  }

  /* (8) コンテナの保持するRSA鍵ペアのハンドルを取得する。 */
  if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
    printErrorAndExit("CryptGetUserKey");
  }

  /* (9) 鍵ハンドルに付随する利用者証明書データのデータ長を取得する。 */
  certLen = 0;
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(1)");
  }

  certData = malloc(certLen);
  if (certData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (10) 鍵ハンドルに付随する利用者証明書データのデータを取得する。 */
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, certData, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(2)");
  }

  printf("Certificate:\n");
  printHex(certData, certLen, TRUE);

  free(certData);

  /* (11) ハッシュオブジェクトの生成 */
  if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
    printErrorAndExit("CryptCreateHash");
  }

  /* (12) 署名対象データのハッシュ値を生成 (本サンプルではダミーデータ使用) */
  memset(hashData, 0xa5, HASHSIZE_SHA1);

  /* (13) ハッシュオブジェクトのパラメータを設定 */
  if (!CryptSetHashParam(hHash, HP_HASHVAL, hashData, 0)) {
    printErrorAndExit("CryptSetHashParam");
  }

  /* (14) ハッシュ値に署名を行った結果のデータ長を取得する。 */
  sigLen = 0;
  if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &sigLen)) {
    printErrorAndExit("CryptSignHash(1)");
  }

  /* (15) 署名用鍵のPINを設定する。 */
  if (!CryptSetProvParam(hProv, PP_SIGNATURE_PIN, pPinData, pinLen)) {
    printErrorAndExit("CryptSetProvParam");
  }

  sigData = malloc(sigLen);
  if (sigData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (16) ハッシュ値に署名を行った結果を取得する。 */
  if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, sigData, &sigLen)) {
    printErrorAndExit("CryptSignHash(2)");
  }

  printf("Signature:\n");
  printHex(sigData, sigLen, FALSE);

  free(sigData);

  /* (17) ハッシュオブジェクト破棄 */
  if (!CryptDestroyHash(hHash)) {
    printErrorAndExit("CryptDestroyHash");
  }

  /* (18) 鍵ハンドルを破棄する。 */
  if (!CryptDestroyKey(hKey)) {
    printErrorAndExit("CryptDestroyKey");
  }

  /* (19) プロバイダハンドルを解放する。 */
  if (!CryptReleaseContext(hProv, 0)) {
    printErrorAndExit("CryptReleaseContext");
  }
}


/*=====================================================================*/
/*                    Start of main()                             */
/*=====================================================================*/

int main(int argc, char *argv[])
{
  LPCTSTR pProvName;
  BYTE* pPin;
  DWORD pinLen;

  /*--------------------*/
  /* (A) 引数のチェック */
  /*--------------------*/

  if (argc != 4)
  {
    printf("実行形式が正しくありません。\n");
    PrintUsage();
    exit(EXIT_SUCCESS);
  }

  /* CSP確認
   * auth : 電子認証用CSP
   * sign : 電子署名用CSP
  */
  switch (*argv[1]) {
  case 'a':
  case 'A':
    pProvName = APROVNAME;
    break;
  case 's':
  case 'S':
    pProvName = SPROVNAME;
    break;
  default:
    printf("実行パラメータ<prov_type>が正しくありません。\n");
    PrintUsage();
    exit(EXIT_FAILURE);
    break;
  }

  /* PIN */
  pPin = argv[3];
  pinLen = strlen(argv[3]);

  /*--------------------*/
  /* (B) 処理の実行    */
  /*--------------------*/

  switch (*argv[2]) {
    /* 証明書取得 */
  case 'g':
  case 'G':
    printf("証明書取得処理 開始\n");
    getCert(pProvName);
    printf("\n証明書取得処理 成功\n");
    break;
    /* 署名 */
  case 's':
  case 'S':
    printf("署名処理 開始\n");
    sign(pProvName, pPin, pinLen);
    printf("\n署名処理 成功\n");
    break;
  default:
    printf("実行パラメータ<method>が正しくありません。\n");
    PrintUsage();
    exit(EXIT_FAILURE);
    break;
  }

  exit(EXIT_SUCCESS);
}
/*=====================================================================*/
/*             End of main()                   */
/*=====================================================================*/