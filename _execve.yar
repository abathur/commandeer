import "magic"
import "macho"

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
