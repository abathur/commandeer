import "magic"
import "elf"
import "macho"

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
private rule macho_binary
{
	condition:
		executable and magic.type() contains "Mach-O "
}

private rule elf_binary
{
	condition:
		(executable or shared_object) and magic.type() contains "ELF "
}

private rule elf_binary_static
{
	condition:
		elf_binary and magic.type() contains "statically linked"
}

// "GLIBC" might be able to separate further if needed
private rule elf_binary_dynamic
{
	condition:
		elf_binary and magic.type() contains "dynamically linked"
}

rule binary
{
	condition:
		elf_binary or macho_binary
}

rule go_binary
{
	// TODO:
	// - convert to hex
	// - add conditional underscore
	// - match nul bytes
    // these are also present in both versions (but w/o underscore)
    // __gosymtab
    // __gopclntab
    strings:
        $gosymtab = "gosymtab"
        $gopclntab = "gopclntab"
        //               g  o  .  b  u  i  l  d  i  d
        $buildid = { 00 67 6f 2e 62 75 69 6c 64 69 64 00 }
    condition:
        binary and 1 of them //or magic.type() contains "Go BuildID"
}

rule elf_binary_dynamic_glibc
{
	strings:
		$ = "GLIBC"
	condition:
		elf_binary_dynamic and any of them
}

rule elf_binary_dynamic_unexpected_noglibc
{
	condition:
		elf_binary_dynamic and not elf_binary_dynamic_glibc
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

rule go_exec
{
    strings:
        $ = "exec_unix.go"
        $ = "os/exec"
    condition:
        go_binary and 1 of them
}

// strings:
//         //  00 6578 6563 7665 00 // seems to *usually* be surrounded by 00;
//         // be aware that this could also be padding (but it looks stableish)
//         // note, the @@GLIBC is the part that'll get stripped; don't be tempted to rely on it
//         // $elf = "execve"
//         //           e  x  e  c  v  e      @ @
//         $elf = { 00 65 78 65 63 76 65 (00|4040) }
rule elf_execve
{
    // TODO: AFAIK all I need is the below, but it's worth testing whether a naive
    // string match on execve as a precondition helps this miss faster?
    condition:
        binary and for any i in (0..elf.dynsym_entries): (elf.dynsym[i].name matches /^execve/)
}

rule macho_execve
{
    strings:
    // idk which form is more desirable; first is obviously
    // more self-documenting
    //$mac = "@_execve" fullword
    // @ _  e x  e c  v e
    //405f 6578 6563 7665 00
    //                  p?
    //405f 6578 6563 7670 // there may be a normative 00 here as well?
    // 2767040, 3335140?
    // $mac = { 40 5F 65 78 65 63 76 65 00 }
    // (781800..781900), (893300..893400), (899600..899700),
    //$mac = "execve"
    $mac = { (00|40) 5F 65 78 65 63 76 65 00 }
    //$mac = { ?? ?? ?? 65 78 65 63 76 65 ?? ?? ??}
    condition:
        binary and for any i in (0..macho.number_of_segments):
            (macho.segments[i].segname == "__LINKEDIT"
            and $mac in (macho.segments[i].fileoff..(macho.segments[i].fileoff + macho.segments[i].fsize)))
}

rule execve
{
    condition:
        go_exec or elf_execve or macho_execve
}
