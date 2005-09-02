ck="../ckmd5"
ret="0"

msg="test1: should print OK"
$ck a.txt > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test2: should print BAD"
$ck b.txt > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test3: should say can't find nfo file"
$ck .avi > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test4: shouldn't print anything"
$ck c.md5 > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test5: shouldn't print anything"
$ck d.nfo > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test6: should say checksum not found"
$ck e.mpg > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test7: should say checksum file not found"
$ck f.ogm > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test8: should print OK"
$ck g.mp3 > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test9: should print BAD"
$ck h.mp3 > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test10: should print OK"
$ck i.abcd > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test11: should print OK"
$ck j > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test12: expecting OK"
$ck -c i.md5 > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test13: expecting OK"
$ck -c k.nfo > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test14: expecting error"
$ck -c l.nfo k.nfo > /dev/null 2>/dev/null
if test "$?" = "0" ; then
    echo "error: $msg"
    ret="-1"
fi

msg="test15: expect success"
$ck foo-cd1-bar.avi > /dev/null 2>/dev/null
if test "$?" != "0" ; then
    echo "error: $msg"
    ret="-1"
fi

if test "$ret" = "0" ; then
    echo "Test successful."
fi

exit $ret
