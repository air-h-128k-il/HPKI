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

/* �v���O�����̎��s�`�� */
void PrintUsage() {
	printf("Usage : HPKISignVerifySampleP11 <PKCS#11 Library_Type> <Pin> \n");
	printf("PKCS#11 Library_Type\t: auth | sign\n");
	printf("Pin\t\t\t: HPKICardPin\n");
}

/* �e�f�[�^(�ؖ����f�[�^�A�����f�[�^)��16�i���\���ŕW���o�� */
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
/* �o�C�i���f�[�^���t�@�C���o��*/
int fileout(const char* outf, const BYTE* data, DWORD len)
{
	FILE *fp;
	if (fopen_s(&fp,outf, "wb") != 0) {  /* �t�@�C���̃I�[�v�� */
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
	/*  �����̃`�F�b�N    */
	/*--------------------*/

	if (argc != 3)
	{
		printf("���s�`��������������܂���B\n");
		PrintUsage();
		return(RETURN_FAILURE);
	}
	
	/* HPKI P11���C�u�����̑I��*/
	switch (*(argv[1])) {
		/*�d�q�F�ؗp*/
	case 'a':
	case 'A':
		pPkcs11LibraryName = "HpkiAuthP11_MPKCS11H.dll";
		break;
		/*�d�q�����p*/
	case 's':
	case 'S':
		pPkcs11LibraryName = "HpkiSigP11_MPKCS11H.dll";
		break;
	default:
		printf("���s�p�����[�^<PKCS#11 Library_Type>������������܂���B\n");
		PrintUsage();
		exit(EXIT_FAILURE);
		break;
	}

	/* PIN */
	pUserPin = (CK_UTF8CHAR_PTR)*(argv + 2);
	userPinLen = (CK_ULONG)strlen((const char *)*(argv + 2));


	/*-----------------------------*/
	/*		��������			   */
	/*-----------------------------*/

	/*	(1) �I�����ꂽHPKI P11���C�u�����̃��[�h	*/
	instance = LoadLibrary((LPCTSTR)pPkcs11LibraryName);
	if (instance == NULL)
	{
		printf("Error in %s() : %08x\n", "LoadLibrary", GetLastError());
		goto m_end;
	}

	loadLibraryFlag = TRUE;

	/*	(2) ���삳���邽�߂�DLL���̊֐����擾	*/
	procAddress = GetProcAddress(instance, (LPCTSTR)"C_GetFunctionList");
	if (procAddress == NULL)
	{
		printf("Error in %s() : %08x\n", "GetProcAddress", GetLastError());
		goto m_end;
	}

	/*	(3) �֐��̃|�C���^���X�g�̎擾	*/
	rv = ((C_GetFunctionListFuncPtr)(procAddress))(&pFunctionList);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_GetFunctionList", rv);
		goto m_end;
	}

	/*	(4) HPKI P11���C�u����������������	*/
	rv = (pFunctionList->C_Initialize)(NULL_PTR);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_Initialize", rv);
		goto m_end;
	}

	initializeFlag = TRUE;

	/*--------------------------------------*/
	/*		�ؖ����擾�ɑ΂��鏉������		*/
	/*--------------------------------------*/

	/*	(5) �X���b�g���X�g���擾����(����������) */
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

	/*	(6) �X���b�g���X�g���擾���� */
	rv = (pFunctionList->C_GetSlotList)(TRUE, slotID, &slotCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(2) : %08x\n", "C_GetSlotList", rv);
		goto m_end;
	}

	/*	(7) �擪�̃X���b�g�ɑ΂���Z�b�V�������m������ */
	rv = (pFunctionList->C_OpenSession)(slotID[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_OpenSession", rv);
		goto m_end;
	}

	openSessionFlag = TRUE;


	/*--------------------------------------*/
	/*	 �ؖ����擾����						*/
	/*--------------------------------------*/
	
	printf("�ؖ����擾���� �J�n\n");

	/* ���������̐ݒ� */
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

	/*	(8) �I�u�W�F�N�g�̌����̏����� */
	rv = (pFunctionList->C_FindObjectsInit)(sessionHandle, findTemplate, findTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsInit_cert", rv);
		goto m_end;
	}

	findObjectsFlag = TRUE;

	/*	(9) �I�u�W�F�N�g�̌������s���A�擪�̏ؖ������w�肷�� */
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

	/* �����̐ݒ� */
	attributeTemplate[0].type = CKA_VALUE;
	attributeTemplate[0].pValue = NULL_PTR;
	attributeTemplate[0].ulValueLen = 0;

	/*	(10) �I�u�W�F�N�g�̑����l���擾���A�ؖ����̃T�C�Y���擾 */
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

	/*	(11) �������̊m�ۂ��s���A�ؖ������擾���� */
	certificateLen = attributeTemplate[0].ulValueLen;
	pCertificate = (unsigned char *)malloc((size_t)certificateLen);

	if (pCertificate == NULL)
	{
		printf("Memory Allocation Failure\n");
		goto m_end;
	}

	/* �ؖ����̎擾 */
	attributeTemplate[0].pValue = (CK_BYTE_PTR)pCertificate;

	rv = (pFunctionList->C_GetAttributeValue)(sessionHandle, certificateObjectHandle, attributeTemplate, attributeTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s(2) : %08x\n", "C_GetAttributeValue", rv);
		goto m_end;
	}

	/*	(12) �I�u�W�F�N�g�̌������I������ */
	findObjectsFlag = FALSE;

	rv = (pFunctionList->C_FindObjectsFinal)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsFinal_cert", rv);
		goto m_end;
	}

	/* �ؖ����f�[�^��\�� */
	printf("Certificate:\n");
	printHex(pCertificate, certificateLen, TRUE);
	/* �ؖ����f�[�^���t�@�C���o�� */
	//rv = fileout("c:\\temp\\EEcert.der", pCertificate, certificateLen);
	if (rv != 0)
	{
		printf("Cetificate File Out Failure\n");
		goto m_end;
	}
	printf("�ؖ����擾���� ����: %s\n\n", pLabel);


	/*----------------------------------------------*/
	/*	��������									*/
	/*----------------------------------------------*/
	
	printf("�������� �J�n\n");

	/*	(13) �擪�̃X���b�g�̃g�[�N�������擾���� */
	rv = (pFunctionList->C_GetTokenInfo)(slotID[0], &tokenInfo);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_GetTokenInfo", rv);
		goto m_end;
	}

	/*	(14) �Í��g�[�N���Ƀ��O�C������ */
	if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) != FALSE) {
		rv = (pFunctionList->C_Login)(sessionHandle, CKU_USER, pUserPin, userPinLen);
		if (rv != CKR_OK)
		{
			printf("Error in %s() : %08x\n", "C_Login", rv);
			goto m_end;
		}

		loginFlag = TRUE;
	}


	/*	(15) �Í��g�[�N�����̏��������p�閧���̌���������ݒ� */
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

	/*	(16) �I�u�W�F�N�g�̌����̏����� */
	rv = (pFunctionList->C_FindObjectsInit)(sessionHandle, findTemplate, findTemplateCount);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsInit_key", rv);
		goto m_end;
	}

	findObjectsFlag = TRUE;

	/*	(17) �I�u�W�F�N�g�̌������s���A�擪�̔閧�����擾���� */
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

	/*	(18) �I�u�W�F�N�g�̌������I������ */
	findObjectsFlag = FALSE;
	rv = (pFunctionList->C_FindObjectsFinal)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_FindObjectsFinal_key", rv);
		goto m_end;
	}

	/* ���������̏����� */

	/*	(19) �������s���f�[�^�̐��� */
	pMessage = "hello-world";
	messageLen = (CK_ULONG)strlen((const char *)pMessage);

	/*	(20) �����Ώۃ��b�Z�[�W�̃n�b�V���l�𐶐� */
	SHA256(pMessage, messageLen, hash);
	printf("SHA256 HASH:\n");
	printHex(hash, SHA256_DIGEST_LENGTH, FALSE);
	printf("\n");
	//rv = fileout("c:\\temp\\hash.dat", hash, SHA256_DIGEST_LENGTH);

	/*	(21) �n�b�V���l��DigestInfo���� */
	sig.algor = &algor;
	sig.algor->algorithm = OBJ_nid2obj(NID_sha256);
	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;
	sig.digest = &digest;
	sig.digest->data = (unsigned char *)hash;
	sig.digest->length = SHA256_DIGEST_LENGTH;
	len = i2d_X509_SIG((X509_SIG *)&sig, &der);

	/*	(22) �������J�j�Y���̐ݒ� */
	signatureMechanism.mechanism = CKM_RSA_PKCS;
	signatureMechanism.pParameter = NULL_PTR;
	signatureMechanism.ulParameterLen = 0;

	/*	(23) ���������̏����� */
	rv = (pFunctionList->C_SignInit)(sessionHandle, &signatureMechanism, privateKeyObjectHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_SignInit", rv);
		goto m_end;
	}

	/*	(24) �f�[�^�ɏ������s�� */
	rv = (pFunctionList->C_Sign)(sessionHandle, der, len, signature, &signatureLen);
	if (rv != CKR_OK)
	{
		printf("Error in %s() : %08x\n", "C_Sign", rv);
		goto m_end;
	}

	/* �����f�[�^��\�� */
	printf("Signature:\n");
	printHex(signature, signatureLen, FALSE);
	printf("�������� ����\n\n");
	//rv = fileout("c:\\temp\\sig.dat", signature, signatureLen);

	/*++++++++++++++++++++++++++++++++++++++++++*/
	/*	�������l�̊m�F		 Start				*/
	/*++++++++++++++++++++++++++++++++++++++++++*/
	
	printf("���؏��� �J�n\n");

	struct rsa_st *pRsaPlivateKey = NULL;

	/*	(25) �������̊m�� */
	pBioCertificate = BIO_new_mem_buf((void *)pCertificate, (int)certificateLen);
	if (pBioCertificate == NULL)
	{
		printf("Error in %s() : NULL\n", "BIO_new_mem_buf");
		goto m_end;
	}

	/*	(26) ���J���ؖ����̕��� */
	pX509Certificate = d2i_X509_bio(pBioCertificate, NULL);
	if (pX509Certificate == NULL)
	{
		printf("Error in %s() : NULL\n", "d2i_X509_bio");
		goto m_end;
	}

	/*	(27) ���J���̎擾 */
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

	/*	(28) �������� */
	rc = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signatureLen, pRsaPublicKey);
	if (rc != 1)
	{
		printf("���؏��� ���s\n");
		printf("ErrorCode : %08x\n", ERR_get_error()); //04091068
 		goto m_end;
	}

	printf("���؏��� ����\n");

	/*	(29) ���J���̉��  */
	RSA_free(pRsaPublicKey);
	pRsaPublicKey = NULL;

	EVP_PKEY_free(pEvpPublicKey);
	pEvpPublicKey = NULL;

	/*	(30) ���J���ؖ����̉��  */
	X509_free(pX509Certificate);
	pX509Certificate = NULL;

	/*	(31) �������̈�̉��  */
	BIO_free(pBioCertificate);
	pBioCertificate = NULL;

	/*++++++++++++++++++++++++++++++++++++++++++*/
	/*	�������l�̊m�F		 End				*/
	/*++++++++++++++++++++++++++++++++++++++++++*/

	/*-----------------------------*/
	/*	 �I������				   */
	/*-----------------------------*/

	/*	(32) �ؖ����̉�� */
	free(pCertificate);
	pCertificate = NULL;

	/*	(33) �Í��g�[�N������̃��O�A�E�g */
	loginFlag = FALSE;

	rv = (pFunctionList->C_Logout)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_Logout(", rv);
		goto m_end;
	}

	/*	(34) �Z�b�V�����̃N���[�Y */
	openSessionFlag = FALSE;

	rv = (pFunctionList->C_CloseSession)(sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_CloseSession", rv);
		goto m_end;
	}

	/*	(35) HPKI P11���C�u�����̏I�� */
	initializeFlag = FALSE;

	rv = (pFunctionList->C_Finalize)(NULL_PTR);
	if (rv != CKR_OK)
	{
		printf("Error in %s(1) : %08x\n", "C_Finalize", rv);
		goto m_end;
	}

	/*	(36) HPKI P11���C�u�����̉�� */
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
	/*	�G���[�������̏I������		 */
	/*-------------------------------*/

	/*----------------------------*/
	/* ���J���̉��(�G���[������) */
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
	/* ���J���ؖ����̉��(�G���[������) */
	/*----------------------------------*/

	if (pX509Certificate != NULL)
	{
		X509_free(pX509Certificate);
		pX509Certificate = NULL;
	}

	/*--------------------------------*/
	/* �������̈�̉��(�G���[������) */
	/*--------------------------------*/

	if (pBioCertificate != NULL)
	{
		BIO_free(pBioCertificate);
		pBioCertificate = NULL;

	}

	/*-----------------------------*/
	/*	�ؖ����̉��(�G���[������) */
	/*-----------------------------*/

	if (pCertificate != NULL)
	{
		free(pCertificate);
		pCertificate = NULL;
	}

	/*---------------------------------------------*/
	/*	�Í��g�[�N������̃��O�A�E�g(�G���[������) */
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
	/*	�Z�b�V�����̃N���[�Y(�G���[������) */
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
	/*	HPKI P11���C�u�����̏I��(�G���[������) */
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
	/*	HPKI P11���C�u�����̉��(�G���[������) */
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
