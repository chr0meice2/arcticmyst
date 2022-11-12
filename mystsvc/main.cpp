//#define WINVER 0x0600
//#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <msi.h>
#include <psapi.h>
#include <lmcons.h>
#include <sddl.h>
#include <wintrust.h>
#include <Softpub.h>
#include <shlobj.h>
//#include <algorithm>
#include <random>
#include <atomic>
#include <algorithm>
#include <wincrypt.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "resource.h"
#define PCRE2_STATIC
#define PCRE2_CODE_UNIT_WIDTH 8
#include "C:/pcre2-10.40/src/pcre2.h"
#include "t:/deeptide/mystsvc/hashes.h"

static const char EXPLORER[]="explorer.exe";
static const char ARCTIC[]="arcticmyst.exe";

static bool AlreadyLoadedMainExe=false;

static  std::atomic< bool>FreeUpgrade=false;
static CRITICAL_SECTION UpgradeCritical;


static void launch_and_get_output2(char * cmdline_in,std::string &outbuf);
void WINAPI SafeUnhookParams(void *dummy);

static decltype( SafeUnhookParams) *myReal_SafeUnhook=nullptr;

template <size_t charCount>
void strcpy_safe(char (&output)[charCount], const char* pSrc)
{
	strncpy(output, pSrc, charCount);
	output[charCount-1] = 0;
}


static bool	WFClean=false;
static bool	WSClean=false;


const char injectLibraryPath64[]="C:\\programdata\\arcticmyst\\MystHookProc64.dll";
const char Path64Hash[]=_hash64;
const char injectLibraryPath32[]="C:\\programdata\\arcticmyst\\MystHookProc32.dll";	
const char Path32Hash[]=_hash32;

static const char DOMAIN[]="deeptide.com";
static const char FAIL[]="[NA]";
static const char PA_MD5[]="ab50d8d707b97712178a92bbac74ccc2a5699eb41c17aa77f713ff3e568dcedb";
static const char PA_PATH[]="C:\\programdata\\arcticmyst\\paexec.exe";
static const char MAIN_MD5[]=_mainexe;
static const char MAIN_PATH[]="C:\\programdata\\arcticmyst\\arcticmyst.exe";
static const char UPG_PATH[]="C:\\programdata\\arcticmyst\\mystinstaller.exe";
static CHAR TUPG_PATH[]="C:\\programdata\\arcticmyst\\paexec.exe -s -i -d C:\\programdata\\arcticmyst\\mystinstaller.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES";


const unsigned  THIS_VERSION=1;
const unsigned short MY_PORT=443;


static CHAR SVCNAME[]= "ArcticMyst";

static SERVICE_STATUS          gSvcStatus; 
static SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
static HANDLE                  ghSvcStopEvent = NULL;

static std::string SystemPath="";


static void GetSystemPath();
static std::string ws2s( const std::wstring &wstr );
static void EjectProcesses();
static char* GetProcAddressEx( HANDLE hProcess , HMODULE hModule ,const char* pzName );
static void SecEngProcEnumerator_All(std::vector<DWORD> &ProcID32,std::vector<DWORD> &ProcID64);
static void EjectDLL(DWORD nProcessId, const char* wsDLLPath);

static DWORD SecEngProcEnumerator(const char *filter);


static std::string PCRE2_Extract_One_Submatch(const std::string pattern,const std::string &subject,const bool multi);
static void WolfAlert(const char *domain,const unsigned short port,std::string &POST,std::string &response);
static bool ReadAndHash(const char *path,std::string &HashIn); 
VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler (DWORD);
DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);
DWORD WINAPI UpdateThread (LPVOID lpParam);
static void Cleanup();
static std::string replace_regex(const std::string &RegexIn, const std::string& TextBlock, const std::string& dummy);
static bool comparei(std::string input1,std::string input2);

static void logdata(const char *path,const std::string &MyBuf);

static VOID WINAPI SvcCtrlHandler( DWORD ); 
static VOID WINAPI SvcMain( DWORD, LPTSTR * ); 

static VOID ReportSvcStatus( DWORD, DWORD, DWORD );
static VOID SvcInit(  ); 


static VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{

   switch(dwCtrl) 
   {  
      case SERVICE_CONTROL_STOP: 
         ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

         // Signal the service to stop.

         SetEvent(ghSvcStopEvent);
         ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
         
         return;
 
      case SERVICE_CONTROL_INTERROGATE: 
         break; 
 
      default: 
         break;
   } 

}
static VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{

	UNREFERENCED_PARAMETER(dwArgc);
	UNREFERENCED_PARAMETER(lpszArgv);



    gSvcStatusHandle = RegisterServiceCtrlHandler( 
        SVCNAME, 
        SvcCtrlHandler);

    if( !gSvcStatusHandle )
    { 

        return; 
    } 


    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    gSvcStatus.dwServiceSpecificExitCode = 0;    

    // Report initial status to the SCM



   ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );



    // Perform service-specific initialization and work.

    SvcInit(  );

}

static VOID ReportSvcStatus( DWORD dwCurrentState,
                      DWORD dwWin32ExitCode,
                      DWORD dwWaitHint)
{

    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.

    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ( (dwCurrentState == SERVICE_RUNNING) ||
           (dwCurrentState == SERVICE_STOPPED) )
        gSvcStatus.dwCheckPoint = 0;
    else gSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );

}
static VOID SvcInit( )
{


    ghSvcStopEvent = CreateEvent(
                         NULL,    // default security attributes
                         TRUE,    // manual reset event
                         FALSE,   // not signaled
                         NULL);   // no name

    if ( ghSvcStopEvent == NULL)
    {
        ReportSvcStatus( SERVICE_STOPPED, GetLastError(), 0 );


        return;
    }

    // Report running status when initialization is complete.


    ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

	WSADATA wsaData;
   	if(WSAStartup(MAKEWORD(2,2),&wsaData)!=0)
    {

		return;
    }
	WSClean=true;
	if(wolfSSL_Init() != SSL_SUCCESS)
	{

		Cleanup();
		return;
	}
	WFClean=true;

	#define InitCriticalSection( _NAME , _FREESUF ) \
		InitializeCriticalSectionAndSpinCount(&_NAME, 0x0); \
		Free##_FREESUF=true;


	InitCriticalSection( UpgradeCritical               ,Upgrade     );
	#undef InitCriticalSection



	HANDLE uThread = CreateThread (NULL, 0, UpdateThread, NULL, 0, NULL);
	if(uThread==0)
	{
		Cleanup();
		return;
	}
	CloseHandle(uThread);

    HANDLE hThread = CreateThread (NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
	if(hThread==0)
	{
		Cleanup();
		return;
	}
	CloseHandle(hThread);

//	OutputDebugStringA("test");

    // TO_DO: Perform work until service stops.

    while(1)
    {
        // Check whether to stop the service.

        WaitForSingleObject(ghSvcStopEvent, INFINITE);

        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
		Cleanup(); // is this correct?
        return;
    }

}


int __cdecl main(int argc, char *argv[]) 
{



	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	const DWORD Len = UNLEN;
	char szUsername[Len + 1]{};
	DWORD dwLen = Len;

	if (   (GetUserNameA( szUsername, &dwLen)==0)    )
	{
		return 0;
	}

	std::string UCheck=szUsername;
	if(UCheck!="SYSTEM")
	{
		return 0;
	}

	GetSystemPath();
	if(SystemPath.empty() )
	{

		return 0;
	}
	if( ! (SystemPath[0]=='c' || SystemPath[0]=='C')   )
	{

		return 0;
	}



	std::string buildpath=SystemPath;
	buildpath+="\\cmd.exe /c ver";

	if(buildpath.size() >512)
	{
		return 0;
	}

	char winver[1024]{};
	strcpy_safe(winver,buildpath.c_str());

	std::string verOutput="";
	launch_and_get_output2(winver,verOutput);
	if(verOutput.empty())
	{
		return 0;
	}

	std::string ParsedVer=PCRE2_Extract_One_Submatch("\\x5bVersion\\x20(\\d+)[\\x2e\\x5d]",verOutput ,false);
	if(   ( ParsedVer.empty()  )|| (ParsedVer==FAIL)   )
	{
		return 0;
	}

	unsigned verint=atoi(ParsedVer.c_str() );
	if(verint<10)
	{
		return 0;
	}




    SERVICE_TABLE_ENTRY DispatchTable[] = 
    { 
        { SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain }, 
        { NULL, NULL } 
    }; 


 
    // This call returns when the service has stopped. 
    // The process should simply terminate when the call returns.

    if (!StartServiceCtrlDispatcher( DispatchTable )) 
    { 

        return 0;
    } 


 
    return 0;
}







DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)
{
	UNREFERENCED_PARAMETER(lpParam);
    //  Periodically check if the service has been requested to stop
    while (WaitForSingleObject(ghSvcStopEvent, 0) != WAIT_OBJECT_0)
    {        
				//OutputDebugStringA("entered run check");
				STARTUPINFO si;
				PROCESS_INFORMATION pi;
				ZeroMemory( &si, sizeof(si) );
				si.cb = sizeof(si);
				ZeroMemory( &pi, sizeof(pi) );
				CHAR path[]="C:\\programdata\\arcticmyst\\paexec.exe -s -i -d C:\\programdata\\arcticmyst\\arcticmyst.exe";

				std::string PAHashOut="";
				std::string MainHashOut="";
				if( (AlreadyLoadedMainExe==true) && (SecEngProcEnumerator(EXPLORER)==0) && (SecEngProcEnumerator(ARCTIC)==0)  )
				{
					AlreadyLoadedMainExe=false; //the user must have quit or logged out.... OK to rerun
					goto failed; 
				}

				if( (SecEngProcEnumerator(EXPLORER)==0) && (SecEngProcEnumerator(ARCTIC)==0) )
				{
					goto failed;
				}

				if(AlreadyLoadedMainExe==true)
				{
					goto failed;
				}


				if( ReadAndHash(PA_PATH,PAHashOut) == false)
				{
					goto failed;
				}
				if(PAHashOut!=PA_MD5)
				{
					goto failed;
				}
				if( ReadAndHash(MAIN_PATH,MainHashOut) == false)
				{
					goto failed;
				}
				if(MainHashOut!=MAIN_MD5)
				{
					goto failed;
				}
			//	OutputDebugStringA("launch before critical");
				//make sure we are not running the existing arcticmyst.exe when an upgrade is happening
				EnterCriticalSection(&UpgradeCritical);
			//	OutputDebugStringA("running arcticmyst");
				if( !CreateProcessA(NULL,path,NULL,NULL,FALSE,0,0,NULL,&si,&pi))
				{
					LeaveCriticalSection(&UpgradeCritical);
					goto failed;
				}

				WaitForSingleObject( pi.hProcess, INFINITE );
				if(pi.hProcess!=0)
				{
					CloseHandle( pi.hProcess );
				}
				if(pi.hThread!=0)
				{
					CloseHandle( pi.hThread );
				}
			//	OutputDebugStringA("done run check");
				LeaveCriticalSection(&UpgradeCritical);
				AlreadyLoadedMainExe=true; //CreateProcess worked for main EXE -- don't load it over and over


		failed:
		Sleep(10000);
    }
 
    return ERROR_SUCCESS;
} 

DWORD WINAPI UpdateThread (LPVOID lpParam)
{

	UNREFERENCED_PARAMETER(lpParam);
	while (WaitForSingleObject(ghSvcStopEvent, 0) != WAIT_OBJECT_0)
	{
		const char PACKET_STRUCTURE[]=" HTTP/1.1\r\nHost: deeptide.com\r\nUser-Agent: ArcticMyst\r\n\r\n";
		std::string MyVersionReply="";

		std::string VERSION_PACKET="GET /cgi-bin/mystversion.cgi";
		VERSION_PACKET+=PACKET_STRUCTURE;

		WolfAlert(DOMAIN,MY_PORT,VERSION_PACKET,MyVersionReply);
		//|2:https://deeptide.com/mystinstaller.exe:98fccbcfe58d5c5f4698a6a7b3e8ea96|	


		std::string RootResponse=PCRE2_Extract_One_Submatch("^(\\x7c\\d{1,5}\\x3a\\x2f[a-z\\d\\x2e]+\\x3a[a-f\\d]{64}\\x7c)$",MyVersionReply,true);

		//logdata(RootResponse.c_str());

		std::string ExtractionVersion="";
		std::string ExtractURL="";
		std::string ExtractHash="";
		std::string BuildRequest="GET ";
		std::string EXEResponse="";
		std::string UPG_HASH="";
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		unsigned RemoteVersion=0;
		STARTUPINFO tsi;
		PROCESS_INFORMATION tpi;


		char KillProc[1024]{};

		std::string buildpath=SystemPath;



		//	TCHAR KillProc[]="taskkill.exe /IM arcticmyst.exe /F";

		if(   ( RootResponse.empty()   )  ||  (RootResponse==FAIL)  )
		{
			goto Failed2;
		}

		ExtractionVersion=PCRE2_Extract_One_Submatch("^\\x7c(\\d+)\\x3a\\x2f[a-z\\d\\x2e]+\\x3a[a-f\\d]{64}\\x7c$",RootResponse,false);
		if(   ( ExtractionVersion.empty()   )  ||  (ExtractionVersion==FAIL)  )
		{
			goto Failed2;
		}
		ExtractURL=PCRE2_Extract_One_Submatch("^\\x7c\\d+\\x3a(\\x2f[a-z\\d\\x2e]+)\\x3a[a-f\\d]{64}\\x7c$",RootResponse,false);
		if(   ( ExtractURL.empty()   )  ||  (ExtractURL==FAIL)  )
		{
			goto Failed2;
		}
		ExtractHash=PCRE2_Extract_One_Submatch("^\\x7c\\d+\\x3a\\x2f[a-z\\d\\x2e]+\\x3a([a-f\\d]{64})\\x7c$",RootResponse,false);
		if(   ( ExtractHash.empty()   )  ||  (ExtractHash==FAIL)  )
		{
			goto Failed2;
		}

		RemoteVersion=atoi(ExtractionVersion.c_str());
		if(RemoteVersion>THIS_VERSION)
		{

			BuildRequest+=ExtractURL;
			BuildRequest+=PACKET_STRUCTURE;
			WolfAlert(DOMAIN,MY_PORT,BuildRequest,EXEResponse);
			std::string blank="";
			std::string FixedResponse=replace_regex("^HTTP\\x2f1\\x2e1\\x20200\\x20OK[\\x00-\\xff]*?\r\n\r\n",EXEResponse,blank);
			logdata(UPG_PATH,FixedResponse );
		    if (  ReadAndHash(UPG_PATH,UPG_HASH) ==false)
			{
				goto Failed2;
			}
			if(UPG_HASH!=ExtractHash)
			{
				goto Failed2;
			}


			ZeroMemory( &si, sizeof(si) );
			si.cb = sizeof(si);
			ZeroMemory( &pi, sizeof(pi) );

			ZeroMemory( &tsi, sizeof(tsi) );
			tsi.cb = sizeof(tsi);
			ZeroMemory( &tpi, sizeof(tpi) );

			std::string PAHashOut2="";
			if( ReadAndHash(PA_PATH,PAHashOut2) == false)
			{
					goto Failed2;
			}
			if(PAHashOut2!=PA_MD5)
			{
				goto Failed2;
			}

			//only upgrade if explorer is running
			if(SecEngProcEnumerator(EXPLORER)==0)
			{
					goto Failed2;
			}
		

			buildpath+="\\taskkill.exe /IM arcticmyst.exe /F";
		
			if(buildpath.size() >512)
			{
				goto Failed2;
			}
		
		
			strcpy_safe(KillProc,buildpath.c_str());
	
			EnterCriticalSection(&UpgradeCritical);
		//	OutputDebugStringA("ejecting from svc");

			if( !CreateProcessA(NULL,KillProc,NULL,NULL,FALSE,0,0,NULL,&tsi,&tpi))
			{
					LeaveCriticalSection(&UpgradeCritical);
					goto Failed2;
			}


			EjectProcesses();
		//	OutputDebugStringA("ejecting in svc done");
			if( !CreateProcessA(NULL,TUPG_PATH,NULL,NULL,FALSE,0,0,NULL,&si,&pi))
			{
					LeaveCriticalSection(&UpgradeCritical);
					goto Failed2;
			}

			WaitForSingleObject( pi.hProcess, INFINITE );
			if(pi.hProcess!=0)
			{
				CloseHandle( pi.hProcess );
			}
			if(pi.hThread!=0)
			{
				CloseHandle( pi.hThread );
			}
		//	OutputDebugStringA("done launching upg");
			LeaveCriticalSection(&UpgradeCritical);

		}

		Failed2:
		Sleep(60000);
	}
	return 0;
}

static std::string replace_regex(const std::string &RegexIn, const std::string& TextBlock,  const std::string& temp)
{
	std::string string_outT;
	int numErr;
	size_t erroffset;
 	pcre2_code *RegexObj = pcre2_compile(reinterpret_cast<PCRE2_SPTR8>( RegexIn.c_str() ), PCRE2_ZERO_TERMINATED,PCRE2_CASELESS |PCRE2_MULTILINE, &numErr,&erroffset,NULL);
	if(!RegexObj)
	{
		return string_outT;
	}
	unsigned int offset = 0;
	unsigned int len    = TextBlock.size();
	size_t StackLen = 0;
	unsigned char *outbuffer = NULL;
	pcre2_match_data*  match_data = nullptr;
	match_data =	pcre2_match_data_create_from_pattern(RegexObj, NULL);
	if(match_data==NULL)
	{
		if(RegexObj)
		{
			pcre2_code_free(RegexObj);
		}
		return string_outT;
	}

	int rc = pcre2_substitute(RegexObj, reinterpret_cast<PCRE2_SPTR8>  (TextBlock.c_str() ), len, offset, (PCRE2_SUBSTITUTE_GLOBAL | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH |PCRE2_NOTEMPTY), match_data,NULL,  reinterpret_cast<PCRE2_SPTR8> (    temp.c_str()  ) , temp.size(), outbuffer, &StackLen);
	if(rc != PCRE2_ERROR_NOMEMORY)
	{

		if(match_data)
		{

	 		pcre2_match_data_free(match_data );	
		}
		if(RegexObj)
		{
			pcre2_code_free(RegexObj);
		}
		//MessageBox(0,"test","test",0);
		return string_outT;
	}
	string_outT.resize(StackLen);
	rc = pcre2_substitute(RegexObj,  reinterpret_cast<PCRE2_SPTR8> ( TextBlock.c_str()   ), len, offset, (PCRE2_SUBSTITUTE_GLOBAL | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH |PCRE2_NOTEMPTY), match_data,NULL, reinterpret_cast<PCRE2_SPTR8> (   temp.c_str()   ), temp.size(),  reinterpret_cast< unsigned char*> (   const_cast< char*  > (string_outT.c_str())  ) , &StackLen);

	string_outT.resize(StackLen);
	if(match_data)
	{

	 pcre2_match_data_free(match_data );	
	}

	if(RegexObj)
	{
		pcre2_code_free(RegexObj);
	}
	return string_outT;

}
static void logdata(const char *path,const std::string &MyBuf)
{

	 HANDLE hFile = CreateFile(path,                // name of the write
	                       GENERIC_WRITE,          // open for writing
	                       0,                      // do not share
	                       NULL,                   // default security
	                       CREATE_ALWAYS,             // create new file only
	                       FILE_ATTRIBUTE_NORMAL,  // normal file
	                       NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		return;
	}

	DWORD dwBytesWritten=0;
	DWORD dwBytesToWrite = MyBuf.size();
	WriteFile( 
	                    hFile,           // open file handle
	                    &MyBuf[0],      // start of data to write
	                    dwBytesToWrite,  // number of bytes to write
	                    &dwBytesWritten, // number of bytes that were written
	                    NULL);

	CloseHandle(hFile);


}

static bool ReadAndHash(const char *path,std::string &HashIn)
{

	unsigned BUFSIZE=1024;
	unsigned MD5LEN=32;

    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[1024]{};
    //memset(rgbFile,0x0,BUFSIZE);
    char MD5CHAR[65]{};
   // memset(MD5CHAR,0x0,33);

    DWORD cbRead = 0;
    BYTE rgbHash[32]{};
    //memset(rgbHash,0x0,MD5LEN);
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    hFile = CreateFileA(path,GENERIC_READ, FILE_SHARE_READ,NULL,OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
    {
		return false;
    }



    if (!CryptAcquireContextA(&hProv,NULL, NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))
    {
    	

    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	(*CloseHandle)(hFile);
    	}
        return false;
    }

    


    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {

    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	CloseHandle(hFile);
    	}

        CryptReleaseContext(hProv, 0);
        return false;
    }



    while ((bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {

            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
    		if(hFile!=INVALID_HANDLE_VALUE)
    		{
        		CloseHandle(hFile);
    		}
            return false;
        }
    }

    if (!bResult)
    {

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	CloseHandle(hFile);
    	}
        return false;
    }

    cbHash = MD5LEN;
	HashIn="";
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
    	
    	
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(MD5CHAR,"%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
            HashIn+=MD5CHAR;
        }
			


    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    if(hFile!=INVALID_HANDLE_VALUE)
    {
    	CloseHandle(hFile);
    }



    return true;
	
}




static void WolfAlert(const char *domain,const unsigned short port,std::string &POST,std::string &response)
{

	if(POST.empty())
	{

		return;
	}

	int received=0;
	int TotalReceived=0;
	response="";

    int                sockfd=0;
    struct sockaddr_in sa{};
  	//memset(&sa, 0, sizeof(sa));
    char               buff[256]{};
   	//memset(buff, 0, sizeof(buff));
    //size_t             len;
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
	long long unsigned int ret;
	struct hostent *h;
    h=gethostbyname(domain);
    if(h==0)
    {

         return;
    }


 	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{



         return;
    }


	memcpy((char *)&sa.sin_addr,(char *)h->h_addr,sizeof(sa.sin_addr));
	sa.sin_family=h->h_addrtype;
	sa.sin_port=htons(port);


 	if (connect(sockfd, (struct sockaddr*) &sa, sizeof(sa))== -1)
	{

		 closesocket(sockfd);
	     return;
    }




    if((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()))==NULL)
	{

         closesocket(sockfd);
		return;
    }


	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);

    if ((ssl = wolfSSL_new(ctx)) == NULL)
	{
		closesocket(sockfd);
		wolfSSL_CTX_free(ctx); 
		return ;
    }



    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS)
	{


		closesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return;
    }




    if (wolfSSL_connect(ssl) != SSL_SUCCESS) 
	{


		closesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return ;

    }



	ret = wolfSSL_write(ssl, POST.c_str(),POST.size());
	if(ret!=POST.size())
	{
	

		closesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return;

	}




	while(1)
	{
		memset(buff,0x0,sizeof(buff));
		received=wolfSSL_read(ssl,buff,sizeof(buff)-1);
		if(received==-1)
		{
			goto cleanup;
		}
		if(received>0)
		{
			response.append(buff,received);
			TotalReceived+=received;
		}
	}


	cleanup:

	//OutputDebugStringA("close");
    closesocket(sockfd);



	//OutputDebugStringA("wolfSSL_free");
    wolfSSL_free(ssl);      

	//OutputDebugStringA("wolfSSL_CTX_free");
    wolfSSL_CTX_free(ctx); 


        

	return;
}


static std::string PCRE2_Extract_One_Submatch(const std::string pattern,const std::string &subject,const bool multi)
{


		std::string retval1=FAIL;

		PCRE2_SPTR IPNewpattern = reinterpret_cast<PCRE2_SPTR>(pattern.c_str());
	    int Newerrorcode;
		PCRE2_SIZE Newerroroffset;
		pcre2_code *IPNewre = nullptr;
		if(!multi)
		{
			IPNewre = pcre2_compile(IPNewpattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS |PCRE2_DUPNAMES | PCRE2_UTF, &Newerrorcode, &Newerroroffset, NULL);
		}
		else
		{
			IPNewre = pcre2_compile(IPNewpattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS |PCRE2_DUPNAMES | PCRE2_MULTILINE| PCRE2_UTF, &Newerrorcode, &Newerroroffset, NULL);
		}

		if (!IPNewre)
		{
			
			return retval1;
		}
	
		PCRE2_SPTR Newsubject =   reinterpret_cast<PCRE2_SPTR>(subject.c_str());
		uint32_t Newgroupcount = 0;
		pcre2_pattern_info(IPNewre, PCRE2_INFO_CAPTURECOUNT, &Newgroupcount);
	
		pcre2_match_data *Newmatch_data = pcre2_match_data_create_from_pattern(IPNewre, NULL);
		if(Newmatch_data==NULL)
		{
			if(IPNewre)
			{
				pcre2_code_free(IPNewre);
			}

			return retval1;
		}
		uint32_t Newoptions_exec = 0;
		PCRE2_SIZE Newsubjectlen = strlen( reinterpret_cast<const char*> (Newsubject));
		Newerrorcode = pcre2_match(IPNewre, Newsubject, Newsubjectlen, 0, Newoptions_exec, Newmatch_data, NULL);
		while (Newerrorcode >= 0) 
		{
	
			PCRE2_UCHAR *Newresult;
			PCRE2_SIZE Newresultlen;
			for (uint32_t  i = 0; i <= Newgroupcount; ++i) 
			{
				if(       (i==1)   &&     (pcre2_substring_get_bynumber(Newmatch_data, i, &Newresult, &Newresultlen) ==0)        )
				{

					retval1= reinterpret_cast<const char*> ( Newresult);
					pcre2_substring_free(Newresult);
					break;
				}
	
			} //end for loop has groups matches
			// Advance through subject, making sure not to get stuck at zero-length matches
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(Newmatch_data);
			if (ovector[0] == ovector[1]) 
			{
				Newoptions_exec |= PCRE2_NOTEMPTY_ATSTART;
			} else 
			{
				Newoptions_exec &= !PCRE2_NOTEMPTY_ATSTART;
			}
			Newerrorcode = pcre2_match(IPNewre, Newsubject, Newsubjectlen, ovector[1], Newoptions_exec, Newmatch_data, NULL);
		            
		} //end while loop has matches
		pcre2_match_data_free(Newmatch_data);
	
		if(IPNewre)
		{
			pcre2_code_free(IPNewre);
		}



	return retval1;
}


static void Cleanup()
{


	if(WSClean==true)
	{
		WSACleanup();
	}
	if(WFClean==true)
	{
		wolfSSL_Cleanup(); 
	}
	if(FreeUpgrade==true)
	{
		DeleteCriticalSection(&UpgradeCritical);
	}
	return;

}




static void SecEngProcEnumerator_All(std::vector<DWORD> &ProcID32,std::vector<DWORD> &ProcID64)
{

	PROCESSENTRY32 ProcStruct;
	HANDLE ToolHelpHandle = INVALID_HANDLE_VALUE;
	ToolHelpHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return;
	}
	ProcStruct.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(ToolHelpHandle, &ProcStruct))
	{
		if (ToolHelpHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ToolHelpHandle);
		}
		return;
	}
	do
	{

		//std::string pexe = ProcStruct.szExeFile;
	//	if (        (comparei("winlogon.exe", pexe) == false) && (comparei("lsass.exe", pexe) == false)    )
	//	{
	//	if (        (comparei("a.exe", pexe) == true)    )
	//	{
			HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION, false, ProcStruct.th32ProcessID);
			if(h)
			{
	
				BOOL BitCheck=FALSE;
				BOOL ret= IsWow64Process(h,&BitCheck);
				if(ret!=0)
				{
				//	printf("%s",ProcStruct.szExeFile);
				//	printf("%s","\n\n");
					if(BitCheck==FALSE)
					{
						//MessageBox(0,std::to_string(ProcStruct.th32ProcessID).c_str(),"asdf",0);
						ProcID64.push_back(ProcStruct.th32ProcessID);
					}
					else
					{
						ProcID32.push_back(ProcStruct.th32ProcessID);
					}
				}
	
			}
			CloseHandle(h);
	//	}



	} while (Process32Next(ToolHelpHandle, &ProcStruct));
	if (ToolHelpHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ToolHelpHandle);
	}
	return ;
}



// MySoft genius work=)
static char* GetProcAddressEx( HANDLE hProcess , HMODULE hModule ,const char* pzName ) {
    
    #define _PageSz 4096
    #define _p(_pp_) ((char*)(_pp_))
        
    //printf("IMAGE_DOS_HEADER=%i\n",sizeof(IMAGE_DOS_HEADER));
    //printf("IMAGE_NT_HEADERS=%i\n",sizeof(IMAGE_NT_HEADERS));
    //printf("IMAGE_OPTIONAL_HEADER=%i\n",sizeof(IMAGE_OPTIONAL_HEADER));
    //printf("IMAGE_EXPORT_DIRECTORY=%i\n",sizeof(IMAGE_EXPORT_DIRECTORY)); 
    
    char bFirstPage[_PageSz]; //store first page for identification
    if (!ReadProcessMemory( hProcess , ((char*)hModule) , bFirstPage , _PageSz , 0 )) {
        //printf("Read failed at %p+%08X\n",(void*)hModule,0);
        return NULL;
    };
    
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)(bFirstPage); 
    IMAGE_NT_HEADERS32 *pNTHeader32; IMAGE_OPTIONAL_HEADER32 *pOptHeader32;
    IMAGE_NT_HEADERS64 *pNTHeader64; IMAGE_OPTIONAL_HEADER64 *pOptHeader64; 
    
    size_t iModuleSz; BOOL Is64bit = FALSE;
    
    pNTHeader32 = (IMAGE_NT_HEADERS32*)(_p(pDosHeader) + pDosHeader->e_lfanew);
  switch (pNTHeader32->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_AMD64: Is64bit = TRUE; break;
        case IMAGE_FILE_MACHINE_I386: break;
        default: /*puts("Unknown machine");*/ ; return 0;
    }   
    
    if (Is64bit) {
        pNTHeader64 = (IMAGE_NT_HEADERS64*)(_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader64 = (IMAGE_OPTIONAL_HEADER64*)(&(pNTHeader64->OptionalHeader));
        iModuleSz = ((pOptHeader64->SizeOfImage) & (~_PageSz));
    } else {
        pNTHeader32 = (IMAGE_NT_HEADERS32*)(_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader32 = (IMAGE_OPTIONAL_HEADER32*)(&(pNTHeader32->OptionalHeader));
        iModuleSz = ((pOptHeader32->SizeOfImage) & (~_PageSz));
    }   
    
    char* pModule = (char*)malloc(iModuleSz);   
    char* pPages = (char*)calloc(iModuleSz/_PageSz,1);
    memcpy( pModule+(0*_PageSz) ,  bFirstPage , _PageSz ) ; pPages[0]=1;
    
    /*
    // --- loading whole library from remote??? --- //
    for ( size_t N=0 ; N<iSz ; N+=_PageSz ) {
        if (!ReadProcessMemory( hProcess , ((char*)hModule)+N , pModule+N , _PageSz , 0 )) {
            printf("Read failed at %p+%08X\n",(void*)hModule,N);            
        };
    };
    */
    
    pDosHeader = (IMAGE_DOS_HEADER*) (_p(pModule)); 
    IMAGE_EXPORT_DIRECTORY *pExports;
    
    #define _pRVA(_pp_) (_p(pDosHeader)+((UINT)(_pp_)))
    #define _pDirectory32RVA(_N_) (pOptHeader32->DataDirectory[_N_].VirtualAddress)
    #define _pDirectory64RVA(_N_) (pOptHeader64->DataDirectory[_N_].VirtualAddress) 
    
    //macro to copy pages from remote process on demand!!!
    #define _LoadRVA(_OFF) { \
        DWORD iPage = (_OFF)/_PageSz , iPageOff = iPage*_PageSz; \
        if (((iPageOff)<iModuleSz) && (!pPages[iPage])) { \
            if (!ReadProcessMemory( hProcess , ((char*)hModule)+iPageOff , pModule+iPageOff , _PageSz , 0 )) { \
              ;  /*printf("Read failed at %p+%08X\n",(void*)hModule,iPageOff);*/ \
            } else { \
                pPages[iPage] = 1; \
            } \
            iPage += 1; iPageOff += _PageSz; \
            if (((iPageOff)<iModuleSz) && (!pPages[iPage])) { \
                if (ReadProcessMemory( hProcess , ((char*)hModule)+iPageOff , pModule+iPageOff , _PageSz , 0 )) { \
                    pPages[iPage] = 1; \
                } \
            } \
        } \
    }   
    
    //IMAGE_NT_HEADERS64 and IMAGE_OPTIONAL_HEADER64 are different between x86 and x86-64
    DWORD dwExportsDirectoryRVA;
    if (Is64bit) {
        pNTHeader64 = (IMAGE_NT_HEADERS64*) (_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader64 = (IMAGE_OPTIONAL_HEADER64*) (&(pNTHeader64->OptionalHeader));
        dwExportsDirectoryRVA = _pDirectory64RVA(IMAGE_DIRECTORY_ENTRY_EXPORT);     
    } else {
        pNTHeader32 = (IMAGE_NT_HEADERS32*) (_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader32 = (IMAGE_OPTIONAL_HEADER32*) (&(pNTHeader32->OptionalHeader));
        dwExportsDirectoryRVA = _pDirectory32RVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
    }   
 
    //set export directory local pointer and load its page
    _LoadRVA(dwExportsDirectoryRVA);    
    pExports = (IMAGE_EXPORT_DIRECTORY *)_pRVA(dwExportsDirectoryRVA);
    
  //local pointer for names and address
  //RVA is loaded later as required.    
    LPDWORD pdName = (LPDWORD)_pRVA(pExports->AddressOfNames);
    LPDWORD pdAddress = (LPDWORD)_pRVA(pExports->AddressOfFunctions);
    LPWORD pwNumToAddr = (LPWORD)_pRVA(pExports->AddressOfNameOrdinals);
    
    #define _pRemRVA(_pp_) (_p(hModule)+((UINT)(_pp_))) 
    #define _pRemAddress(_N_) _p(_pRemRVA(pdAddress[pwNumToAddr[_N_]]))
    
    //Locating Export name
    char *pResult = NULL;
    for ( DWORD N = 0 ; N<pExports->NumberOfNames ; N++ ) {             
        _LoadRVA( (pExports->AddressOfNames+N*sizeof(DWORD)) ); //load RVA for name addresses
        DWORD dwNameRVA = pdName[N];
        _LoadRVA( dwNameRVA ); //load for name characters
        if (!strcmp((char*)_pRVA(dwNameRVA),pzName)) { 
            _LoadRVA( (pExports->AddressOfNameOrdinals+N*sizeof(DWORD)) )
            DWORD dwNumRVA = pwNumToAddr[N];
            _LoadRVA( (pExports->AddressOfFunctions+dwNumRVA*sizeof(DWORD)) )
            //function address
            pResult = _pRemAddress(N);  break; 
        }
    }   
    
    free(pModule); free(pPages);
    return pResult;
    
    #undef _p
    #undef _pRVA
    #undef _pRemRVA
    #undef _pDirectory32RVA
    #undef _pDirectory64RVA 
    #undef _pRemAddress     
    #undef _LoadRVA
}




static void EjectDLL(DWORD nProcessId, const char* wsDLLPath)
{



	void* nBaseAddress = 0;
	HANDLE hThread, hProcess;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, nProcessId);
	if (hProcess)
	{
		DWORD cbNeeded=0;
		HMODULE hMods[1024];
		unsigned int i=0;
		if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				CHAR wszModName[MAX_PATH]{};
				if (GetModuleFileNameExA(hProcess, hMods[i], wszModName,	sizeof(wszModName) / sizeof(CHAR)))
				{
					//MessageBoxA(0,wszModName,"test",0);
					if (lstrcmp(wszModName, wsDLLPath) == 0)
					{


						MODULEINFO modInfo;
						memset(&modInfo, 0, sizeof(modInfo));
						if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
						{

	
							nBaseAddress = modInfo.lpBaseOfDll;
							//MessageBoxA(0,std::to_string(nBaseAddress).c_str(),"asd",0);
							//DWORD SafeUnhook_Offset=0;

							//SafeUnhook_Offset=((LONG_PTR)myReal_SafeUnhook)-((LONG_PTR)m2.myhook.handle);

							myReal_SafeUnhook=(decltype(SafeUnhookParams)*)((void*)GetProcAddressEx(hProcess,hMods[i],"SafeUnhook"));
							//hThread = CreateRemoteThread(hProcess, NULL, 1024*1024, (LPTHREAD_START_ROUTINE)nBaseAddress+SafeUnhook_Offset, nBaseAddress, 0, NULL);
							hThread = CreateRemoteThread(hProcess, NULL, 1024*1024, (LPTHREAD_START_ROUTINE)(INT_PTR)myReal_SafeUnhook, nBaseAddress, 0, NULL);	
							if (hThread)
							{
								WaitForSingleObject(hThread, 2000);
								CloseHandle(hThread);
							}
							break;
						

							
						}
					}
				}
			}
		}


		CloseHandle(hProcess);
		hProcess=INVALID_HANDLE_VALUE;
		//MessageBoxA(0,"gothere","shouldwork",0);
	}
}




static void EjectProcesses()
{


	std::vector<DWORD> p32;
	std::vector<DWORD> p64;
	SecEngProcEnumerator_All(p32,p64);



	if(!p64.empty() )
	{
		for(unsigned p=0;p<p64.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath64,PAHashOut2) == false)
			{
				continue;
			}
			if(PAHashOut2!=Path64Hash)
			{
				continue;
			}
			EjectDLL(p64[p],injectLibraryPath64);
		}
	}

	if(! p32.empty() )
	{
		for(unsigned p=0;p<p32.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath32,PAHashOut2) == false)
			{
				continue;
			}
			if(PAHashOut2!=Path32Hash)
			{
				continue;
			}
			EjectDLL(p32[p],injectLibraryPath32);
		}
	}


	return;
}


static DWORD SecEngProcEnumerator(const char *filter)
{
	DWORD retval=0;
	PROCESSENTRY32 ProcStruct;
	HANDLE ToolHelpHandle = INVALID_HANDLE_VALUE;
	ToolHelpHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return retval;
	}
	ProcStruct.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(ToolHelpHandle, &ProcStruct))
	{
		if (ToolHelpHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ToolHelpHandle);
		}
		return retval;
	}
	do
	{
		std::string pexe = ProcStruct.szExeFile;
		if (comparei(filter, pexe) == true)
		{
			retval=ProcStruct.th32ProcessID;
			break;
		}

	} while (Process32Next(ToolHelpHandle, &ProcStruct));
	if (ToolHelpHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ToolHelpHandle);
	}
	return retval;
}


static bool comparei(std::string input1,std::string input2)
{
	transform(input1.begin(), input1.end(), input1.begin(), ::toupper);
	transform(input2.begin(), input2.end(), input2.begin(), ::toupper);
	return (input1 == input2);
}

static std::string ws2s( const std::wstring &wstr )
{
    // get length
    int length = WideCharToMultiByte( CP_UTF8, 0,wstr.c_str(), wstr.size(),   NULL, 0,  NULL, NULL );
    if( !(length > 0) )
	{
        return std::string();
	}
    else
    {

        std::string result;
        result.resize( length );
		if(result.empty() )
		{
			return std::string();
		}

        if( WideCharToMultiByte( CP_UTF8, 0,wstr.c_str(), wstr.size(), &result[0], result.size(),NULL, NULL ) > 0 )
        {
			return result;
		}
        else
		{
            return std::string();
		}

    }

   return std::string();

}

static void GetSystemPath()
{

	PWSTR path = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_System, 0, NULL, &path);

    if (hr!=S_OK)
	{
		return;
    }


	std::wstring wide_string = path;
	 std::string temppath= ws2s(path);
	if(!temppath.empty() )
	{
		SystemPath=temppath;
	}

    (*CoTaskMemFree)(path);	

}



static void launch_and_get_output2(char * cmdline_in,std::string &outbuf)
{

    DWORD bytes_read;
    HANDLE stdoutWriteHandle = 0;
    STARTUPINFO startupInfo{};
    //memset(&startupInfo, 0, sizeof(startupInfo));
    SECURITY_ATTRIBUTES saAttr{};
    PROCESS_INFORMATION processInfo;
    //memset(&saAttr, 0, sizeof(saAttr));
    HANDLE stdoutReadHandle = 0;
    outbuf="";
    DWORD exitcode;
    char tBuf[4097]{};
    //memset(tBuf,0x0,sizeof(tBuf));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&stdoutReadHandle, &stdoutWriteHandle, &saAttr, 0))
    {

        return;
    }
    if (!SetHandleInformation(stdoutReadHandle, HANDLE_FLAG_INHERIT, 0))
    {

    	if(       (stdoutWriteHandle!=INVALID_HANDLE_VALUE)  &&     (stdoutWriteHandle!=0)       )
   	 	{
        	CloseHandle(stdoutWriteHandle);
    	}
    	if(        (stdoutReadHandle!=INVALID_HANDLE_VALUE)     &&    (stdoutReadHandle!=0)      )
   	 	{
             CloseHandle(stdoutReadHandle);
    	}
        return;
    }
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.hStdError = stdoutWriteHandle;
    startupInfo.hStdOutput = stdoutWriteHandle;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.dwFlags |= STARTF_USESTDHANDLES;
    if (!CreateProcessA(NULL, &cmdline_in[0], NULL, NULL, TRUE,CREATE_NO_WINDOW, NULL, 0, &startupInfo, &processInfo))
    {
    
	    	if(       (stdoutWriteHandle!=INVALID_HANDLE_VALUE)  &&     (stdoutWriteHandle!=0)           )
	   	 	{
	        	CloseHandle(stdoutWriteHandle);
	    	}
	    	if(           (stdoutReadHandle!=INVALID_HANDLE_VALUE)     &&    (stdoutReadHandle!=0)   )
	   	 	{
	        	CloseHandle(stdoutReadHandle);
	    	}
	    	if(       (processInfo.hProcess!=INVALID_HANDLE_VALUE)    &&   (processInfo.hProcess!=0)              )
	    	{
	
	        	CloseHandle( processInfo.hProcess );
	    	}
	    	if(    (processInfo.hThread!=INVALID_HANDLE_VALUE)       &&    (processInfo.hThread!=0)               )
	    	{
	
	        	CloseHandle( processInfo.hThread );
	    	}
	
	        return;
	        
	        
       }
       
       

    	if(       (stdoutWriteHandle!=INVALID_HANDLE_VALUE)  &&     (stdoutWriteHandle!=0)           )
   	 	{
        	 CloseHandle(stdoutWriteHandle);
    	}


    
    for (;;) {
    	memset(tBuf,0x0,sizeof(tBuf));
        if (!ReadFile(stdoutReadHandle, tBuf, 4096, &bytes_read, NULL))
        {
        	if(         (stdoutReadHandle!=INVALID_HANDLE_VALUE)    &&       (stdoutReadHandle!=0)         )      
        	{
        		CloseHandle(stdoutReadHandle);
			}
            break;
        }
        if (bytes_read > 0)
        {
        	
        	 
            tBuf[bytes_read] = '\0';
			outbuf+=tBuf;
        }
    }
    

    

    
    if (WaitForSingleObject(processInfo.hProcess, INFINITE) != WAIT_OBJECT_0)
    {
        //////log_error("WaitForSingleObject Pipe",efin);
    	if(  (processInfo.hProcess!=INVALID_HANDLE_VALUE)            && (processInfo.hProcess!=0))
    	{
        	CloseHandle( processInfo.hProcess );
    	}
    	if(    (processInfo.hThread!=INVALID_HANDLE_VALUE)   &&  (processInfo.hThread!=0))
    	{
        	CloseHandle( processInfo.hThread );
    	}
        return;
    }
    if (!GetExitCodeProcess(processInfo.hProcess, &exitcode))
    {
        //////log_error("GetExitProcess error",efin);
    	if(  (processInfo.hProcess!=INVALID_HANDLE_VALUE)            && (processInfo.hProcess!=0))
    	{
        	CloseHandle( processInfo.hProcess );
    	}
    	if(    (processInfo.hThread!=INVALID_HANDLE_VALUE)   &&  (processInfo.hThread!=0))
    	{
        	CloseHandle( processInfo.hThread );
    	}
        return ;
    }
    
    
    
    
    	if(  (processInfo.hProcess!=INVALID_HANDLE_VALUE)            && (processInfo.hProcess!=0))
    	{
        	CloseHandle( processInfo.hProcess );
    	}
    	if(    (processInfo.hThread!=INVALID_HANDLE_VALUE)   &&  (processInfo.hThread!=0))
    	{
        	CloseHandle( processInfo.hThread );
    	}
    
    
    	return;

	
}
