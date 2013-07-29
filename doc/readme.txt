TeaTime/2 v0.06 - A XTea file encryption program

Please check your country's cryptography import/export control laws before
downloading. Both me and the webspace provider have no resposibility for
violation of crypto laws. The person performing the download is responsible
in any case!

* Introduction *

TeaTime/2 is a file encryption program for OS/2 based on the simple, fast
and secure XTea cipher (which is an improved version of the Tiny Encryption
Algorithm). XTea is a block cipher with an 128-bit key, primarily using
32-bit operations making it fast on 386 and later processors. TeaTime/2 is
compiled using the Mill Hill & Canterbury Modula-2 compiler for OS/2.

* Usage *

Syntax: teatime <-d|-e> <input file> <output file> [key]

The key parameter is optional, if it is omitted TeaTime/2 will ask for the
password interactively.

Todo

   * Rewrite in Pascal (probably FreePascal).
   * Support for keyfiles.
   * PM interface.
   * Wildcards (for batch encryption).
   (* Other ciphers.)

Feedback

Please send comments, bug-reports and other feedback to:
daniel@blowgish.org

Feedback is appreciated, even a message telling me it works fine on your
OS/2 version.

Copyright information

Copyright (c) 2001-2002 Daniel de Kok. All rights reserved.
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
