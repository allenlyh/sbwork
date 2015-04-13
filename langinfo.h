/*
Language encode
c		0
c++		1
pascal		2
*/
const char lang_ext[3][10] = {"c", "cpp", "pas"};
const char *compiler[3][11] = {
	{"gcc", "Main.c", "-o", "Main", "-fno-asm", "-Wall", "-lm", "--static", "-std=c99", "-DONLINE_JUDGE", nil}, //c
	{"g++", "Main.cpp", "-o", "Main", "-fno-asm", "-Wall", "-lm", "--static", "-std=c++0x", "-DONLINE_JUDGE", nil }, //c++
	{"fpc", "Main.pas", "-O2", "-Co", "-Ct", "-Ci", nil, nil, nil, nil, nil } //pascal
};
