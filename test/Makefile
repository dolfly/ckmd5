ck = ../ckmd5

all:	test1 test2 test3 test4 test5 test6 test7 test8 test9 test10

test1:	
	@echo "test1: should print OK"
	@ $(ck) a.txt

test2:	
	@echo "test2: should print BAD"
	@ $(ck) b.txt

test3:	
	@echo "test3: should print OK"
	@ $(ck) .avi

test4:	
	@echo "test4: shouldn't print anything"
	@ $(ck) c.md5

test5:	
	@echo "test5: shouldn't print anything"
	@ $(ck) d.nfo

test6:	
	@echo "test6: should say checksum not found"
	@ $(ck) e.mpg

test7:	
	@echo "test7: should say checksum not found"
	@ $(ck) f.ogm

test8:	
	@echo "test8: should print OK"
	@ $(ck) g.mp3

test9:	
	@echo "test9: should print BAD"
	@ $(ck) h.mp3

test10:	
	@echo "test10: should print OK"
	@ $(ck) i.abcd
