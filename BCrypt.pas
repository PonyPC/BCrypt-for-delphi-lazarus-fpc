unit BCrypt;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, RegExpr, DCPblowfish;

function checkPassword(Str: string; Hash: ansistring): boolean;

implementation

const
  BCRYPT_SALT_LEN = 16;
  //bcrypt uses 128-bit (16-byte) salt (This isn't an adjustable parameter, just a name for a constant)

  BsdBase64EncodeTable: array[0..63] of char =
    { 0:} './' +
    { 2:} 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    {28:} 'abcdefghijklmnopqrstuvwxyz' +
    {54:} '0123456789';

  //the traditional base64 encode table:
  //'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
  //'abcdefghijklmnopqrstuvwxyz' +
  //'0123456789+/';

  BsdBase64DecodeTable: array[#0..#127] of integer = (
    {  0:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  // ________________
    { 16:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  // ________________
    { 32:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,
    1,  // ______________./
    { 48:} 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1,
    -1, -1,  // 0123456789______
    { 64:} -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16,  // _ABCDEFGHIJKLMNO
    { 80:} 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1,
    -1, -1,  // PQRSTUVWXYZ_____
    { 96:} -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42,  // _abcdefghijklmno
    {113:} 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1);
// pqrstuvwxyz_____

function BsdBase64Encode(const Data: TBytes; BytesToEncode: integer): ansistring;
var
  i: integer;
  len: integer;
  b1, b2: integer;
begin
  Result := '';

  len := BytesToEncode;
  if (len <= 0) or (len > Length(Data)) then
    Exit;

  i := Low(Data);
  while i < len do
  begin
    b1 := Data[i] and $ff;
    Inc(i);

    Result := Result + BsdBase64EncodeTable[(b1 shr 2) and $3f];
    b1 := (b1 and $03) shl 4;
    if i >= len then
    begin
      Result := Result + BsdBase64EncodeTable[b1 and $3f];
      exit;
    end;

    b2 := Data[i] and $ff;
    Inc(i);
    b1 := ((b2 shr 4) and $0f) or b1;

    Result := Result + BsdBase64EncodeTable[b1 and $3f];
    b1 := (b2 and $0f) shl 2;
    if i >= len then
    begin
      Result := Result + BsdBase64EncodeTable[b1 and $3f];
      exit;
    end;

    b2 := Data[i] and $ff;
    Inc(i);
    b1 := ((b2 shr 6) and $03) or b1;
    Result := Result + BsdBase64EncodeTable[b1 and $3f];
    Result := Result + BsdBase64EncodeTable[b2 and $3f];
  end;
end;

function BsdBase64Decode(const s: ansistring): TBytes;

  function Char64(character: AnsiChar): integer;
  begin
    if Ord(character) > Length(BsdBase64DecodeTable) then
    begin
      Result := -1;
    end
    else
    begin
      Result := BsdBase64DecodeTable[character];
    end;
  end;

  procedure Append(Value: byte);
  var
    i: integer;
  begin
    i := Length(Result);
    SetLength(Result, i + 1);
    Result[i] := Value;
  end;

var
  i: integer;
  len: integer;
  c1, c2, c3, c4: integer;
begin
  SetLength(Result, 0);
  i := 1;
  len := Length(s);
  while i < len do
  begin
    c1 := Char64(s[i]);
    Inc(i);
    c2 := Char64(s[i]);
    Inc(i);
    if (c1 = -1) or (c2 = -1) then
      Exit;

    //Now we have at least one byte in c1|c2
    // c1 = ..111111
    // c2 = ..112222
    Append((c1 shl 2) or ((c2 and $30) shr 4));
    //If there's a 3rd character, then we can use c2|c3 to form the second byte
    if i > len then
      Break;

    c3 := Char64(s[i]);
    Inc(i);
    if (c3 = -1) then
      Exit;

    //Now we have the next byte in c2|c3
    // c2 = ..112222
    // c3 = ..222233
    Append(((c2 and $0f) shl 4) or ((c3 and $3c) shr 2));
    //If there's a 4th caracter, then we can use c3|c4 to form the third byte
    if i > len then
      Break;

    c4 := Char64(s[i]);
    Inc(i);
    if c4 = -1 then
      Exit;

    //Now we have the next byte in c3|c4
    // c3 = ..222233
    // c4 = ..333333
    Append(((c3 and $03) shl 6) or c4);
  end;
end;

function HashPassword(Str: string; Hash: ansistring): ansistring;
begin

end;

function checkPassword(Str: string; Hash: ansistring): boolean;
var
  RegexObj: TRegExpr;
  BlowFish: TDCP_blowfish;
begin
  RegexObj := TRegExpr.Create;
  RegexObj.Expression := '^\$2a\$13\$([\./0-9A-Za-z]{22})';
  if not RegexObj.Exec(Hash) then
  begin
    Result := False;
    RegexObj.Free;
    Exit;
  end;

  RegexObj.Free;
  BlowFish := TDCP_blowfish.Create(nil);
  BlowFish.Init(Str, sizeof(Str) * 8, nil);
  BlowFish.Free;
end;

end.
