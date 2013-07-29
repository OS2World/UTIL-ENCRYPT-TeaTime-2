IMPLEMENTATION MODULE XTea;

(*

This is a Modula-2 implementation of the XTea cipher.

Copyright (c) 2001 Daniel de Kok. All rights reserved.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*)

(*$XL+*)

PROCEDURE XTea_Encrypt(VAR Plain : tBlock; Key : tKey);
VAR y, z, Limit, Sum : LONGCARD;
BEGIN
        y := Plain[0];
        z := Plain[1];
        Limit := DELTA * Cycles;
        Sum := 0;

        WHILE Sum <> Limit DO
                INC(y, (z SHL 4) XOR (z SHR 5) + z XOR Sum + Key[Sum AND 3]);
                Sum := Sum + DELTA;
                INC(z, (y SHL 4) XOR (y SHR 5) + y XOR Sum + Key[(Sum SHR 11) AND 3]);
        END;

        Plain[0] := y;
        Plain[1] := z;
END XTea_Encrypt;

PROCEDURE XTea_Decrypt(VAR Crypted : tBlock; Key : tKey);
VAR y, z, Sum : LONGCARD;
BEGIN
        y := Crypted[0];
        z := Crypted[1];
        Sum := DELTA * Cycles;

        WHILE Sum <> 0 DO
                DEC(z, (y SHL 4) XOR (y SHR 5) + y XOR Sum + Key[(Sum SHR 11) AND 3]);
                Sum := Sum - DELTA;
                DEC(y, (z SHL 4) XOR (z SHR 5) + z XOR Sum + Key[Sum AND 3]);
        END;

        Crypted[0] := y;
        Crypted[1] := z;
END XTea_Decrypt;

PROCEDURE ROTL8(VAR x : LONGCARD);
BEGIN
        x:=(x SHL 8) OR (x SHR 24);
END ROTL8;

PROCEDURE CryptBuf(VAR Buf : ARRAY OF SHORTCARD; Key : tKey; VAR IV : ARRAY OF SHORTCARD; Direction : SHORTCARD; Mode : SHORTCARD);
VAR theBlock : tBlock;
    pos, pos2, pos3, i, j : LONGCARD;
    New_IV : ARRAY[0..7] OF SHORTCARD;

BEGIN
        pos:=0;
        pos2:=0;
        WHILE pos < 4096 DO
                pos3:=0;
                FOR i:=0 TO 1 DO
                        theBlock[i]:=0;
                        FOR j:=0 TO 3 DO
                                IF (Mode = Mode_CBC) AND (Direction = Dir_Encrypt) THEN
                                        Buf[pos]:=Buf[pos] XOR IV[pos3];
                                        INC(pos3);
                                END;
                                IF (Mode = Mode_CBC) AND (Direction = Dir_Decrypt) THEN
                                        New_IV[pos3]:=Buf[pos];
                                        INC(pos3);
                                END;
                                theBlock[i]:=theBlock[i] SHL 8;
                                theBlock[i]:=theBlock[i] OR Buf[pos];
                                INC(pos);
                        END;
                END;

                IF Direction = Dir_Encrypt THEN
                        XTea_Encrypt(theBlock, Key);
                ELSE
                        XTea_Decrypt(theBlock, Key);
                END;

                pos3:=0;
                FOR i:=0 TO 1 DO
                        FOR j:=0 TO 3 DO
                                Buf[pos2]:=0;
                                ROTL8(theBlock[i]);
                                Buf[pos2]:=Buf[pos2] OR SHORT(SHORT(theBlock[i]));
                                IF (Mode = Mode_CBC) AND (Direction = Dir_Encrypt) THEN
                                        IV[pos3]:=0;
                                        IV[pos3]:=IV[pos3] OR SHORT(SHORT(theBlock[i]));
                                        INC(pos3);
                                END;
                                IF (Mode = Mode_CBC) AND (Direction = Dir_Decrypt) THEN
                                        Buf[pos2]:=Buf[pos2] XOR IV[pos3];
                                        INC(pos3);
                                END;
                                INC(pos2);
                        END;
                END;

                IF (Mode = Mode_CBC) AND (Direction = Dir_Decrypt) THEN
                        FOR i:=0 TO BlockSize-1 DO
                                IV[i]:=New_IV[i];
                        END;
                END;
        END;
END CryptBuf;

PROCEDURE SimpleHash(VAR CharKey : ARRAY OF CHAR);
VAR Key : tKey;
    CharKeyBuf : ARRAY[0..4095] OF SHORTCARD;
    IV : ARRAY[0..BlockSize-1] OF SHORTCARD;
    i,j : CARDINAL;
BEGIN
        (* Use a static key *)
        Key[0]:=4849;
        Key[1]:=9483829;
        Key[2]:=29379930;
        Key[3]:=22;

        (* Generate an IV *)
        FOR i:=0 TO BlockSize-1 DO
                IV[i]:=SHORT(i*12);
        END;

        (* Fill the buffer with the key *)
        FOR i:=0 TO 4095 BY KeyLen DO
                FOR j:=0 TO KeyLen-1 DO
                        CharKeyBuf[i+j]:=ORD(CharKey[j]);
                END;
        END;

        CryptBuf(CharKeyBuf, Key, IV, Dir_Encrypt, Mode_CBC);

        (* Use last 8 bytes as key *)
        FOR i:=4095-KeyLen TO 4095 DO
                CharKey[i-(4095-KeyLen)]:=CHAR(CharKeyBuf[i]);
        END;
END SimpleHash;

BEGIN
END XTea.
