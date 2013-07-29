MODULE TeaTime;

(*$XL+*)

(*

TeaTime/2 - A XTea file encryption program

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

IMPORT InOut, Strings, OS2ARG, FileSystem, XTea;

CONST ProgName = 'TeaTime/2 v0.06 - A XTea file encryption program';
      ProgCopyright = 'Copyright (c)2001-2002 Daniel de Kok';
      ProgUsage = 'Usage: teatime <-d|-e> <input file> <output file> [key]';
      ProgErrorOpen = 'Could not open input file!';
      ProgErrorCreate = 'Could not create output file!';
      ProgPassPrompt = 'Password: ';

PROCEDURE Help();
BEGIN
        InOut.WriteString(ProgUsage);
        InOut.WriteLn;
END Help;

PROCEDURE Encrypt(InFileName, OutFileName : ARRAY OF CHAR; Key : XTea.tKey);
VAR InFile, OutFile : FileSystem.File;
    Buf : ARRAY[0..4095] OF SHORTCARD;
    IV : ARRAY[0..7] OF SHORTCARD;
    i : SHORTCARD;
    FileSize : LONGCARD;
    LastBlockSize : CARDINAL;
BEGIN
        FOR i:=0 TO XTea.BlockSize-1 DO
                IV[i]:=i*11;
        END;

        FileSystem.Lookup(InFile, InFileName, FALSE);
        IF InFile.res <> 0 THEN
                InOut.WriteString(ProgErrorOpen);
                HALT;
        END;
        FileSystem.Create(OutFile, OutFileName);
        IF OutFile.res <> 0 THEN
                InOut.WriteString(ProgErrorCreate);
                HALT;
        END;


        (* Main encryption loop *)
        WHILE InFile.eof <> TRUE DO
                FileSystem.ReadBlock(InFile, Buf);
                XTea.CryptBuf(Buf, Key, IV, XTea.Dir_Encrypt, XTea.Mode_CBC);
                FileSystem.WriteBlock(OutFile, Buf);
        END;

        (* Write descriptive block *)
        FileSystem.LongLength(InFile, FileSize);
        LastBlockSize:=SHORT(FileSize MOD 4096);
        Buf[0]:=SHORT(LastBlockSize);
        LastBlockSize:=LastBlockSize SHR 8;
        Buf[1]:=SHORT(LastBlockSize);
        XTea.CryptBuf(Buf, Key, IV, XTea.Dir_Encrypt, XTea.Mode_CBC);
        FileSystem.WriteBlock(OutFile, Buf);

        FileSystem.Close(InFile);
        FileSystem.Close(OutFile);
END Encrypt;

PROCEDURE Decrypt(InFileName, OutFileName : ARRAY OF CHAR; Key : XTea.tKey);
VAR InFile, OutFile : FileSystem.File;
    Buf, LastBuf : ARRAY[0..4095] OF SHORTCARD;
    IV : ARRAY[0..7] OF SHORTCARD;
    i : SHORTCARD;
    j : LONGCARD;
    FileSize : LONGCARD;
    LastBlockSize : CARDINAL;
BEGIN
        FOR i:=0 TO XTea.BlockSize-1 DO
                IV[i]:=i*11;
        END;

        FileSystem.Lookup(InFile, InFileName, FALSE);
        IF InFile.res <> 0 THEN
                InOut.WriteString(ProgErrorOpen);
                HALT;
        END;
        FileSystem.Create(OutFile, OutFileName);
        IF OutFile.res <> 0 THEN
                InOut.WriteString(ProgErrorCreate);
                HALT;
        END;

        FileSystem.LongLength(InFile, FileSize);

        (* Main buffer decryption loop *)
        FOR j:=1 TO ((FileSize DIV 4096)-2) DO
                FileSystem.ReadBlock(InFile, Buf);
                XTea.CryptBuf(Buf, Key, IV, XTea.Dir_Decrypt, XTea.Mode_CBC);
                FileSystem.WriteBlock(OutFile, Buf);
        END;

        (* Get size of last block and write to OutFile *)
        FileSystem.ReadBlock(InFile, Buf);
        XTea.CryptBuf(Buf, Key, IV, XTea.Dir_Decrypt, XTea.Mode_CBC);
        FileSystem.ReadBlock(InFile, LastBuf);
        XTea.CryptBuf(LastBuf, Key, IV, XTea.Dir_Decrypt, XTea.Mode_CBC);
        LastBlockSize:=LastBuf[1];
        LastBlockSize:=LastBlockSize SHL 8;
        LastBlockSize:=LastBlockSize OR LastBuf[0];
        FOR j:=1 TO LastBlockSize DO
                FileSystem.WriteChar(OutFile, CHR(Buf[j-1]));
        END;

        FileSystem.Close(InFile);
        FileSystem.Close(OutFile);
END Decrypt;

PROCEDURE CharKeyToKey(CharKey : ARRAY OF CHAR; VAR Key : XTea.tKey);
VAR i, j, pos : SHORTCARD;
BEGIN
        pos:=0;
        FOR i:=0 TO 3 DO
                Key[i]:=0;
        END;
        FOR i:=0 TO 3 DO
                FOR j:=0 TO 3 DO
                        Key[i]:=Key[i] SHL 8;
                        Key[i]:=Key[i] OR ORD(CharKey[pos]);
                        IF pos = Strings.Size(CharKey)-1 THEN
                                RETURN;
                        END;
                        INC(pos);
                END;
        END;
END CharKeyToKey;

PROCEDURE GetCharKey(VAR CharKey : ARRAY OF CHAR; KeyLen : SHORTCARD);
VAR pos : SHORTCARD;
    Key : CHAR;
BEGIN
        FOR pos:=0 TO KeyLen-1 DO
                CharKey[pos]:=CHAR(0);
        END;

        pos:=0;
        WHILE pos < KeyLen DO
                InOut.Read(Key);
                IF ORD(Key) = 13 THEN
                        RETURN;
                ELSIF ORD(Key) = 8 THEN
                        IF pos > 0 THEN
                                DEC(pos);
                                CharKey[pos]:=CHAR(0);
                        END;
                ELSE
                        CharKey[pos]:=Key;
                        INC(pos)
                END;
        END;
END GetCharKey;

VAR Param : OS2ARG.PSTRING;
    InFileName, OutFileName, CharKeyArg : OS2ARG.PSTRING;
    CharKey : ARRAY[0..XTea.KeyLen-1] OF CHAR;
    Key : XTea.tKey;
    i : SHORTCARD;
    Break : BOOLEAN;

BEGIN
        InOut.WriteString(ProgName);
        InOut.WriteLn;
        InOut.WriteString(ProgCopyright);
        InOut.WriteLn;
        InOut.WriteLn;
        IF OS2ARG.ArgCount() > 2 THEN
                InFileName:=OS2ARG.Arg(2);
                OutFileName:=OS2ARG.Arg(3);
                IF OS2ARG.ArgCount() = 3 THEN
                        InOut.WriteString(ProgPassPrompt);
                        GetCharKey(CharKey, XTea.KeyLen);
                        InOut.WriteLn;
                ELSE
                        CharKeyArg:=OS2ARG.Arg(4);

                        (* Convert the key argument to a normal charkey *)
                        FOR i:=0 TO XTea.KeyLen-1 DO
                                CharKey[i]:=CHAR(0);
                        END;
                        Break:=FALSE;
                        i:=0;
                        REPEAT
                                CharKey[i]:=CharKeyArg^[i];
                                INC(i);
                                IF ORD(CharKeyArg^[i]) = 0 THEN
                                        Break:=TRUE;
                                ELSIF i > XTea.KeyLen-1 THEN
                                        Break:=TRUE;
                                END;
                        UNTIL Break = TRUE;
                END;

                (* Somehow omitting this breaks things *)
                InOut.Write(CHR(0));

                (* Hash the key and convert it *)
                XTea.SimpleHash(CharKey);
                CharKeyToKey(CharKey, Key);

                Param:=OS2ARG.Arg(1);
                CASE Param^[1] OF
                        'e': Encrypt(InFileName^, OutFileName^, Key);
                        |'d': Decrypt(InFileName^, OutFileName^, Key);
                ELSE
                        Help();
                END;
        ELSE
                Help();
        END;
END TeaTime.
