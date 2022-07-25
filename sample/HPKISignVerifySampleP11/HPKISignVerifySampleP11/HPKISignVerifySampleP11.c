/*---------------------------------------------------------------------*/
/* FILE NAME	:	HPKISignVerifySampleP11.c						   */
/* VERSION		:	1.0												   */
/* DATE			:	2020/11/21										   */
/*---------------------------------------------------------------------*/

/*=====================================================================*/
/*                             INCLUDE	                               */
/*=====================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "pkcs11.h"

#include <malloc.h>
#include <winbase.h>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/rsa.h"
#include "openssl/engine.h"
#include "openssl/objects.h"
#include "openssl/sha.h"
#include "openssl/err.h"

/*=====================================================================*/
/*                             DEFINITION                              */
/*=====================================================================*/

typedef CK_RV(*C_GetFunctionListFuncPtr)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

#define RETURN_SUCCESS           0
#define RETURN_FAILURE           1
#define NUM_SLOT                 4
#define FIND_TEMPLATE_COUNT      3
#define ATTRIBUTE_TEMPLATE_COUNT 1
#define BUFFER_SIZE              512


/*=====================================================================*/
/*              DEFINITIOIN OF PRIVATE FUNCTION						   */
/*=====================================================================*/

/* プログラムの実行形式 */
void PrintUsage() {
	printf("Usage : HPKISignVerifySampleP11 <PKCS#11 Library_Type> <Pin> \n");
	printf("PKCS#11 Library_Type\t: auth | sign\n");
	printf("Pin\t\t\t: HPKICardPin\n");
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
/* バイナリデータをファイル出力*/
int fileout(const char* outf, const BYTE* data, DWORD len)
{
	FILE *fp;
	if (fopen_s(&fp,outf, "wb") != 0) {  /* ファイルのオープン */
		printf("file open error!!\n");
		return 1;
	}
	fwrite(data, len, 1, fp);
	fclose(fp);
	return 0;
}

/*=====================================================================*/
/*                    Start of main()			                       */
/*=====================================================================*/

int main(int argc, char **argv) {

	const char              *pPkcs11LibraryName;

	CK_UTF8CHAR_PTR         pUserPin;
	CK_ULONG                userPinLen;
	CK_BYTE_PTR             pMessage;
	CK_ULONG                messageLen;

	CK_BBOOL                loadLibraryFlag = FALSE;
	CK_BBOOL                initializeFlag = FALSE;
	CK_BBOOL                openSessionFlag = FALSE;
	CK_BBOOL                loginFlag = FALSE;
	CK_BBOOL                findObjectsFlag = FALSE;

	HINSTANCE				instance = NULL;
	FARPROC                 procAddress = NULL;
	BOOL                    freeLibraryRc;

	CK_RV                   rv;
	CK_FUNCTION_LIST_PTR    pFunctionList = NULL;
	CK_ULONG                slotCount;
	CK_SLOT_ID              slotID[NUM_SLOT];
	CK_SESSION_HANDLE       sessionHandle;
	CK_TOKEN_INFO           tokenInfo;

	CK_OBJECT_CLASS         objectClass;
	CK_BBOOL                ckTrue = TRUE;
	CK_ATTRIBUTE            findTemplate[FIND_TEMPLATE_COUNT];
	CK_ULONG                findTemplateCount = FIND_TEMPLATE_COUNT;
	CK_OBJECT_HANDLE        privateKeyObjectHandle;
	CK_ULONG                foundObjectCount;
	CK_UTF8CHAR_PTR         pLabel;
	CK_ULONG                labelLen;

	CK_ATTRIBUTE            attributeTemplate[ATTRIBUTE_TEMPLATE_COUNT];
	CK_ULONG                attributeTemplateCount = ATTRIBUTE_TEMPLATE_COUNT;
	CK_OBJECT_HANDLE        certificateObjectHandle;

	CK_MECHANISM            signatureMechanism;
	CK_BYTE                 signature[BUFFER_SIZE];
	CK_ULONG                signatureLen = BUFFER_SIZE;

	unsigned char           *pCertificate = NULL;
	unsigned long           certificateLen = 0;
	
	BIO						*pBioCertificate = NULL;
	X509                    *pX509Certificate = NULL;
	EVP_PKEY                *pEvpPublicKey = NULL;
	RSA						*pRsaPublicKey = NULL;
	unsigned char           hash[SHA256_DIGEST_LENGTH];
	int                     rc;

	typedef struct X509_sig_st_S {
		X509_ALGOR *algor;
		ASN1_OCTET_STRING *digest;
	}X509_SIG_S;
	X509_SIG_S sig;
	X509_ALGOR algor;
	ASN1_TYPE parameter;
	ASN1_OCTET_STRING digest;
	uint8_t *der = NULL;
	int len;

	/*--------------------*/
	/*  引数のチェック    */
	/*--------------------*/

	if (argc != 3)
	{
		printf("実行形式が正しくありません。\n");
		PrintUsage();
		return(RETURN_FAILURE);
	}
	
	/* HPKI P11ライブラリの選択*/
	switch (*(argv[1])) {
		/*電子認証用*/
	case 'a':
	case 'A':
		pPkcs11LibraryName = "HpkiAuthP11_MPKCS11H.dll";
		break;
		/*電子署名用*/
	case 's':
	case 'S':
		pPkcs11LibraryName = "HpkiSigP11_MPKCS11H.dll";
		break;
	default:
		printf("実行パラメータ<PKCS#11 Library_Type>が正しくありません。\n");
		PrintUsage();
		exit(EXIT_FAILURE);
		break;
	}

	/* PIN */
	pUserPin = (CK_UTF8CHAR_PTR)*(argv + 2);
	userPinLen = (CK_ULONG)strlen((const char *)*(argv + 2));


	/*-----------------------------*/
	/*		初期処理			   */
	/*-----------------------------*/

	/*	(1) 選択されたHPKI P11ライブラリのロード	*/
	instance = LoadLibrary((LPCTSTR)pPkcs11LibraryName);
	if (instance == NULL)
	{
		printf("Error in %s() : %08x\n", "LoadLibrary", GetLastError());
		goto m_end;
	}

	loadLibraryFlag = TRUE;

	/*	(2) 動作させるためのDLL内の関数を取得	*/
	procAddress = GetProcAddress(instance, (LPCTSTR)"C_GetFunctionList");
	if (procAddress == NULL)
	{
		printf("Error in %s() : %08x\n", "GetProcAddress", GetLastError());
		goto m_end;
	}

	/*	(3) 関数のポインタリストの取得	*/
	rv = ((C_GetFunctionListFuncPtr)(procAddress))(&pFunctionList);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_GetFunctionList", rv);
		goto m_end;
	}

	/*	(4) HPKI P11ライブラリを初期化する	*/
	rv = (pFunctionList->C_Initialize)(NULL_PTR);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_Initialize", rv);
		goto m_end;
	}

	initializeFlag = TRUE;

	/*--------------------------------------*/
	/*		証明書取得に対する初期処理		*/
	/*--------------------------------------*/

	/*	(5) スロットリストを取得する(メモリ割当) */
	rv = (pFunctionList->C_GetSlotList)(TRUE, NULL_PTR, &slotCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_GetSlotList", rv);
		goto m_end;
	}

	if (slotCount < 1)
	{
		printf("Invalid Slot Count\n");
		goto m_end;
	}

	/*	(6) スロットリストを取得する */
	rv = (pFunctionList->C_GetSlotList)(TRUE, slotID, &slotCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(2) : %08x\n", "C_GetSlotList", rv);
		goto m_end;
	}

	/*	(7) 先頭のスロットに対するセッションを確立する */
	rv = (pFunctionList->C_OpenSession)(slotID[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_OpenSession", rv);
		goto m_end;
	}

	openSessionFlag = TRUE;


	/*--------------------------------------*/
	/*	 証明書取得処理						*/
	/*--------------------------------------*/
	
	printf("証明書取得処理 開始\n");

	/* 検索条件の設定 */
	objectClass = CKO_CERTIFICATE;
	pLabel = "HPKI END ENTITY CERTIFICATE";
	labelLen = (CK_ULONG)strlen((const char *)pLabel);

	findTemplate[0].type = CKA_CLASS;
	findTemplate[0].pValue = &objectClass;
	findTemplate[0].ulValueLen = sizeof(objectClass);
	findTemplate[1].type = CKA_TOKEN;
	findTemplate[1].pValue = &ckTrue;
	findTemplate[1].ulValueLen = sizeof(ckTrue);
	findTemplate[2].type = CKA_LABEL;
	findTemplate[2].pValue = pLabel;
	findTemplate[2].ulValueLen = labelLen;

	/*	(8) オブジェクトの検索の初期化 */
	rv = (pFunctionList->C_FindObjectsInit)(sessionHandle, findTemplate, findTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsInit_cert", rv);
		goto m_end;
	}

	findObjectsFlag = TRUE;

	/*	(9) オブジェクトの検索を行い、先頭の証明書を指定する */
	rv = (pFunctionList->C_FindObjects)(sessionHandle, &certificateObjectHandle, 1, &foundObjectCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjects_cert", rv);
		goto m_end;
	}

	if (foundObjectCount != 1)
	{
		printf("Certificate Not Found\n");
		goto m_end;
	}

	/* 属性の設定 */
	attributeTemplate[0].type = CKA_VALUE;
	attributeTemplate[0].pValue = NULL_PTR;
	attributeTemplate[0].ulValueLen = 0;

	/*	(10) オブジェクトの属性値を取得し、証明書のサイズを取得 */
	rv = (pFunctionList->C_GetAttributeValue)(sessionHandle, certificateObjectHandle, attributeTemplate, attributeTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_GetAttributeValue", rv);
		goto m_end;
	}

	if (attributeTemplate[0].ulValueLen == 0)
	{
		printf("Invalid Certificate Size\n");
		goto m_end;
	}

	/*	(11) メモリの確保を行い、証明書を取得する */
	certificateLen = attributeTemplate[0].ulValueLen;
	pCertificate = (unsigned char *)malloc((size_t)certificateLen);

	if (pCertificate == NULL)
	{
		printf("Memory Allocation Failure\n");
		goto m_end;
	}

	/* 証明書の取得 */
	attributeTemplate[0].pValue = (CK_BYTE_PTR)pCertificate;

	rv = (pFunctionList->C_GetAttributeValue)(sessionHandle, certificateObjectHandle, attributeTemplate, attributeTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(2) : %08x\n", "C_GetAttributeValue", rv);
		goto m_end;
	}

	/*	(12) オブジェクトの検索を終了する */
	findObjectsFlag = FALSE;

	rv = (pFunctionList->C_FindObjectsFinal)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsFinal_cert", rv);
		goto m_end;
	}

	/* 証明書データを表示 */
	printf("Certificate:\n");
	printHex(pCertificate, certificateLen, TRUE);
	/* 証明書データをファイル出力 */
	//rv = fileout("c:\\temp\\EEcert.der", pCertificate, certificateLen);
	if (rv != 0)
	{
		printf("Cetificate File Out Failure\n");
		goto m_end;
	}
	printf("証明書取得処理 成功: %s\n\n", pLabel);


	/*----------------------------------------------*/
	/*	署名処理									*/
	/*----------------------------------------------*/
	
	printf("署名処理 開始\n");

	/*	(13) 先頭のスロットのトークン情報を取得する */
	rv = (pFunctionList->C_GetTokenInfo)(slotID[0], &tokenInfo);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_GetTokenInfo", rv);
		goto m_end;
	}

	/*	(14) 暗号トークンにログインする */
	if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) != FALSE) {
		rv = (pFunctionList->C_Login)(sessionHandle, CKU_USER, pUserPin, userPinLen);
		if (rv != CKR_OK)
		{
			printf("Error in %s() : %08x\n", "C_Login", rv);
			goto m_end;
		}

		loginFlag = TRUE;
	}


	/*	(15) 暗号トークン中の署名生成用秘密鍵の検索条件を設定 */
	objectClass = CKO_PRIVATE_KEY;
	pLabel = "Private key of HPKI";
	labelLen = (CK_ULONG)strlen((const char *)pLabel);

	findTemplate[0].type = CKA_CLASS;
	findTemplate[0].pValue = &objectClass;
	findTemplate[0].ulValueLen = sizeof(objectClass);
	findTemplate[1].type = CKA_TOKEN;
	findTemplate[1].pValue = &ckTrue;
	findTemplate[1].ulValueLen = sizeof(ckTrue);
	findTemplate[2].type = CKA_LABEL;
	findTemplate[2].pValue = pLabel;
	findTemplate[2].ulValueLen = labelLen;

	/*	(16) オブジェクトの検索の初期化 */
	rv = (pFunctionList->C_FindObjectsInit)(sessionHandle, findTemplate, findTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsInit_key", rv);
		goto m_end;
	}

	findObjectsFlag = TRUE;

	/*	(17) オブジェクトの検索を行い、先頭の秘密鍵を取得する */
	rv = (pFunctionList->C_FindObjects)(sessionHandle, &privateKeyObjectHandle, 1, &foundObjectCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjects_key", rv);
		goto m_end;
	}

	if (foundObjectCount != 1)
	{
		printf("Private Key Not Found\n");
		goto m_end;
	}

	/*	(18) オブジェクトの検索を終了する */
	findObjectsFlag = FALSE;
	rv = (pFunctionList->C_FindObjectsFinal)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsFinal_key", rv);
		goto m_end;
	}

	/* 署名処理の初期化 */

	/*	(19) 署名を行うデータの生成 */
	pMessage = "hello-world";
	messageLen = (CK_ULONG)strlen((const char *)pMessage);

	/*	(20) 署名対象メッセージのハッシュ値を生成 */
	SHA256(pMessage, messageLen, hash);
	printf("SHA256 HASH:\n");
	printHex(hash, SHA256_DIGEST_LENGTH, FALSE);
	printf("\n");
	//rv = fileout("c:\\temp\\hash.dat", hash, SHA256_DIGEST_LENGTH);

	/*	(21) ハッシュ値のDigestInfo生成 */
	sig.algor = &algor;
	sig.algor->algorithm = OBJ_nid2obj(NID_sha256);
	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;
	sig.digest = &digest;
	sig.digest->data = (unsigned char *)hash;
	sig.digest->length = SHA256_DIGEST_LENGTH;
	len = i2d_X509_SIG((X509_SIG *)&sig, &der);

	/*	(22) 署名メカニズムの設定 */
	signatureMechanism.mechanism = CKM_RSA_PKCS;
	signatureMechanism.pParameter = NULL_PTR;
	signatureMechanism.ulParameterLen = 0;

	/*	(23) 署名処理の初期化 */
	rv = (pFunctionList->C_SignInit)(sessionHandle, &signatureMechanism, privateKeyObjectHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_SignInit", rv);
		goto m_end;
	}

	/*	(24) データに署名を行う */
	rv = (pFunctionList->C_Sign)(sessionHandle, der, len, signature, &signatureLen);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_Sign", rv);
		goto m_end;
	}

	/* 署名データを表示 */
	printf("Signature:\n");
	printHex(signature, signatureLen, FALSE);
	printf("署名処理 成功\n\n");
	//rv = fileout("c:\\temp\\sig.dat", signature, signatureLen);

	/*++++++++++++++++++++++++++++++++++++++++++*/
	/*	※署名値の確認		 Start				*/
	/*++++++++++++++++++++++++++++++++++++++++++*/
	
	printf("検証処理 開始\n");

	struct rsa_st *pRsaPlivateKey = NULL;

	/*	(25) メモリの確保 */
	pBioCertificate = BIO_new_mem_buf((void *)pCertificate, (int)certificateLen);
	if (pBioCertificate == NULL)
	{
		printf("Error in %s() : NULL\n", "BIO_new_mem_buf");
		goto m_end;
	}

	/*	(26) 公開鍵証明書の復号 */
	pX509Certificate = d2i_X509_bio(pBioCertificate, NULL);
	if (pX509Certificate == NULL)
	{
		printf("Error in %s() : NULL\n", "d2i_X509_bio");
		goto m_end;
	}

	/*	(27) 公開鍵の取得 */
	pEvpPublicKey = X509_get_pubkey(pX509Certificate);
	if (pEvpPublicKey == NULL)
	{
		printf("Error in %s() : NULL\n", "X509_get_pubkey");
		goto m_end;
	}
	
	pRsaPublicKey = EVP_PKEY_get1_RSA(pEvpPublicKey);
	if (pRsaPublicKey == NULL)
	{
		printf("Error in %s() : NULL\n", "EVP_PKEY_get1_RSA");
		goto m_end;
	}

	/*	(28) 署名検証 */
	rc = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signatureLen, pRsaPublicKey);
	if (rc != 1)
	{
		printf("検証処理 失敗\n");
		printf("ErrorCode : %08x\n", ERR_get_error()); //04091068
 		goto m_end;
	}

	printf("検証処理 成功\n");

	/*	(29) 公開鍵の解放  */
	RSA_free(pRsaPublicKey);
	pRsaPublicKey = NULL;

	EVP_PKEY_free(pEvpPublicKey);
	pEvpPublicKey = NULL;

	/*	(30) 公開鍵証明書の解放  */
	X509_free(pX509Certificate);
	pX509Certificate = NULL;

	/*	(31) メモリ領域の解放  */
	BIO_free(pBioCertificate);
	pBioCertificate = NULL;

	/*++++++++++++++++++++++++++++++++++++++++++*/
	/*	※署名値の確認		 End				*/
	/*++++++++++++++++++++++++++++++++++++++++++*/

	/*-----------------------------*/
	/*	 終了処理				   */
	/*-----------------------------*/

	/*	(32) 証明書の解放 */
	free(pCertificate);
	pCertificate = NULL;

	/*	(33) 暗号トークンからのログアウト */
	loginFlag = FALSE;

	rv = (pFunctionList->C_Logout)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_Logout(", rv);
		goto m_end;
	}

	/*	(34) セッションのクローズ */
	openSessionFlag = FALSE;

	rv = (pFunctionList->C_CloseSession)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_CloseSession", rv);
		goto m_end;
	}

	/*	(35) HPKI P11ライブラリの終了 */
	initializeFlag = FALSE;

	rv = (pFunctionList->C_Finalize)(NULL_PTR);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_Finalize", rv);
		goto m_end;
	}

	/*	(36) HPKI P11ライブラリの解放 */
	loadLibraryFlag = FALSE;

	freeLibraryRc = FreeLibrary(instance);
	if (freeLibraryRc == 0)
	{
		printf("Error in %s(1) : %08x\n", "FreeLibrary", GetLastError());
		goto m_end;
	}

	return(RETURN_SUCCESS);

m_end:



	/*-------------------------------*/
	/*	エラー発生時の終了処理		 */
	/*-------------------------------*/

	/*----------------------------*/
	/* 公開鍵の解放(エラー発生時) */
	/*----------------------------*/

	if (pRsaPublicKey != NULL)
	{
		RSA_free(pRsaPublicKey);
		pRsaPublicKey = NULL;
	}

	if (pEvpPublicKey != NULL)
	{
		EVP_PKEY_free(pEvpPublicKey);
		pEvpPublicKey = NULL;
	}

	/*----------------------------------*/
	/* 公開鍵証明書の解放(エラー発生時) */
	/*----------------------------------*/

	if (pX509Certificate != NULL)
	{
		X509_free(pX509Certificate);
		pX509Certificate = NULL;
	}

	/*--------------------------------*/
	/* メモリ領域の解放(エラー発生時) */
	/*--------------------------------*/

	if (pBioCertificate != NULL)
	{
		BIO_free(pBioCertificate);
		pBioCertificate = NULL;

	}

	/*-----------------------------*/
	/*	証明書の解放(エラー発生時) */
	/*-----------------------------*/

	if (pCertificate != NULL)
	{
		free(pCertificate);
		pCertificate = NULL;
	}

	/*---------------------------------------------*/
	/*	暗号トークンからのログアウト(エラー発生時) */
	/*---------------------------------------------*/

	if (loginFlag == TRUE)
	{
		loginFlag = FALSE;

		rv = (pFunctionList->C_Logout)(sessionHandle);
		if (rv != CKR_OK)
		{
			printf("Error in %s(2) : %08x\n", "C_Logout", rv);
		}
	}

	/*-------------------------------------*/
	/*	セッションのクローズ(エラー発生時) */
	/*-------------------------------------*/

	if (openSessionFlag == TRUE)
	{
		openSessionFlag = FALSE;

		rv = (pFunctionList->C_CloseSession)(sessionHandle);
		if (rv != CKR_OK)
		{
			printf("Error in %s(2) : %08x\n", "C_CloseSession", rv);
		}
	}

	/*-----------------------------------------*/
	/*	HPKI P11ライブラリの終了(エラー発生時) */
	/*-----------------------------------------*/

	if (initializeFlag == TRUE)
	{
		initializeFlag = FALSE;

		rv = (pFunctionList->C_Finalize)(NULL_PTR);
		if (rv != CKR_OK)
		{
			printf("Error in %s(2) : %08x\n", "C_Finalize", rv);
		}
	}

	/*-----------------------------------------*/
	/*	HPKI P11ライブラリの解放(エラー発生時) */
	/*-----------------------------------------*/

	if (loadLibraryFlag == TRUE)
	{
		loadLibraryFlag = FALSE;

		freeLibraryRc = FreeLibrary(instance);
		if (freeLibraryRc == 0)
		{
			printf("Error in %s(2) : %08x\n", "FreeLibrary", GetLastError());
		}
	}

	return(RETURN_FAILURE);
}

/*=====================================================================*/
/*						End of main()			                       */
/*=====================================================================*/
