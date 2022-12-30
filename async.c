#define _WIN32_WINNT 0x0600

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

int main() {

	WSADATA wsaData = {};    
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	
	PADDRINFOEXW DnsResult;
	OVERLAPPED tAsync;
	tAsync.hEvent = CreateEvent( NULL , TRUE , FALSE , NULL );
	ResetEvent( tAsync.hEvent );

	int iResult = GetAddrInfoExW( L"deeptide.com" , NULL , NS_DNS , NULL , NULL , &DnsResult , NULL , &tAsync , NULL , NULL );
	printf("%i\n",iResult);  
	if (iResult == ERROR_IO_PENDING) {
		//it's asynchornous
		if (WaitForSingleObject( tAsync.hEvent , 0 ) != WAIT_OBJECT_0) {
			puts("Timeout!");
			FreeAddrInfoExW( DnsResult );
			puts("ok!");
			getchar();
			return 0;
		}
			
	}
	
	char zIP[32]; DWORD dwIP=32;
	WSAAddressToStringA( DnsResult->ai_addr , DnsResult->ai_addrlen , NULL , zIP , &dwIP );
	printf("'%s'\n",zIP);

	FreeAddrInfoExW( DnsResult );
	
}
