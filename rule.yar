import "magic"

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

/*
Note: an unreadable setuid executable (like sudo) won't have the
      expected type string and won't otherwise be readable
*/
private rule mac_binary
{
	condition:
		executable and magic.type() contains "Mach-O "
}

private rule elf_binary
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

rule execve
{
    strings:
        $mac = "_execve"
        $elf = "execvp"
        //$ = { b0 0b cd 80 }

    condition:
        (mac_binary and $mac) or (elf_binary and $elf)
}
