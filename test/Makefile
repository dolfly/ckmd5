ck = ../ckmd5

all:	test

test:	test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11

test1:	
	@echo "test1: should print OK"
	@ $(ck) a.txt
	@echo

test2:	
	@echo "test2: should print BAD"
	@ $(ck) b.txt || echo "test2 returned error as expected."
	@echo

test3:	
	@echo "test3: should say can't find nfo file"
	@ $(ck) .avi || echo "test3 returned error as expected."
	@echo

test4:	
	@echo "test4: shouldn't print anything"
	@ $(ck) c.md5
	@echo

test5:	
	@echo "test5: shouldn't print anything"
	@ $(ck) d.nfo
	@echo

test6:	
	@echo "test6: should say checksum not found"
	@ $(ck) e.mpg || echo "test6 returned error as expected."
	@echo

test7:	
	@echo "test7: should say checksum file not found"
	@ $(ck) f.ogm || echo "test7 returned error as expected."
	@echo

test8:	
	@echo "test8: should print OK"
	@ $(ck) g.mp3
	@echo

test9:	
	@echo "test9: should print BAD"
	@ $(ck) h.mp3 || echo "test9 returned error as expected."
	@echo

test10:	
	@echo "test10: should print OK"
	@ $(ck) i.abcd
	@echo

test11:	
	@echo "test11: should print OK"
	@ $(ck) j
	@echo
