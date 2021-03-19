import "magic"
import "elf"

// ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /nix/store/hp8wcylqr14hrrpqap4wdrwzq092wfln-glibc-2.32-37/lib/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
private rule executable
{
	condition:
		magic.type() contains "executable"
}

private rule shared_object
{
	condition:
		 magic.type() contains "shared object"
}

private rule binary
{
	condition:
		(executable or shared_object) and magic.type() contains "ELF "
}

private rule script
{
	condition:
		executable and magic.type() contains "script text"
}

private rule shell_script
{
	condition:
		script and magic.type() matches /(POSIX shell|\/bin\/\w*sh) script/
		//script and magic.type() matches /(POSIX shell|wat) script/
}

private rule python_script
{
	condition:
		script and magic.type() matches /(Python|\/bin\/python\S*) script/
}


rule symlink
{
	condition:
		magic.type() contains "symbolic link to"
}

// strings:
//         //  00 6578 6563 7665 00 // seems to *usually* be surrounded by 00;
//         // be aware that this could also be padding (but it looks stableish)
//         // note, the @@GLIBC is the part that'll get stripped; don't be tempted to rely on it
//         // $elf = "execve"
//         //           e  x  e  c  v  e      @ @
//         $elf = { 00 65 78 65 63 76 65 (00|4040) }
rule execve
{
    // TODO: AFAIK all I need is the below, but it's worth testing whether a naive
    // string match on execve as a precondition helps this miss faster?
    condition:
        binary and for any i in (0..elf.symtab_entries): (elf.symtab[i].name matches /^execve/)
}
