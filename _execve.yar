import "magic"

private rule executable
{
	condition:
		magic.type() contains "executable"
}

private rule binary
{
	condition:
		executable and magic.type() contains "Mach-O"
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
        // idk which form is more desirable; first is obviously
        // more self-documenting
        //$mac = "@_execve" fullword
        // @ _  e x  e c  v e
        //405f 6578 6563 7665 00
        //                  p?
        //405f 6578 6563 7670 // there may be a normative 00 here as well?
        $mac = { 40 5F 65 78 65 63 76 65 00 }

    condition:
        binary and 1 of them
}
