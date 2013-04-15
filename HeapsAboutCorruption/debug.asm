.code

__kebreak proc
	int 3
	ret
__kebreak endp

__timestamp proc
	rdtsc
	ret
__timestamp endp

end
