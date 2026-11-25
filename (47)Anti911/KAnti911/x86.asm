.386
.MODEL FLAT, C       
.DATA
.code   

EXTERN 	FilterService@12 : PROC

GetKiFastCallEntry@0  PROC  
		
		mov ecx,176h
		db 0Fh,32h     ;rdmsr 
		ret
GetKiFastCallEntry@0 ENDP


END