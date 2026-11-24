package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "bytes"
 "errors"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func validCipherDigest(s string)bool{b,e:=hex.DecodeString(s);return e==nil&&len(b)==32&&hex.EncodeToString(b)==s}
func privateOutput(path string)(*os.File,error){
 p,e:=filepath.Abs(path);if e!=nil{return nil,e};parent:=filepath.Dir(p);resolved,e:=filepath.EvalSymlinks(parent);info,e2:=os.Stat(parent)
 if e!=nil||e2!=nil||resolved!=parent||!info.IsDir()||info.Mode().Perm()&0077!=0{return nil,storage.ErrInvalidMetadata}
 return os.OpenFile(p,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
}
func saveCipherDownload(source io.Reader,path,expected string)(err error){
 if !validCipherDigest(expected){return storage.ErrInvalidMetadata};f,e:=privateOutput(path);if e!=nil{return e};accepted:=false
 defer func(){err=errors.Join(err,f.Close());if !accepted{err=errors.Join(err,os.Remove(f.Name()))}}()
 h:=sha256.New();n,e:=io.Copy(io.MultiWriter(f,h),io.LimitReader(source,48*1024*1024+1));if e!=nil{return e};if n==0||n>48*1024*1024||hex.EncodeToString(h.Sum(nil))!=expected{return storage.ErrJournalConflict};if e=f.Sync();e!=nil{return e};accepted=true;return nil
}
func readVerificationReport(path string)(storage.VerificationReport,error){
 var r storage.VerificationReport;p,e:=filepath.Abs(path);if e!=nil{return r,e};resolved,e:=filepath.EvalSymlinks(p);i,e2:=os.Stat(p);if e!=nil||e2!=nil||resolved!=p||!i.Mode().IsRegular()||i.Mode().Perm()&0077!=0||i.Size()>8192{return r,storage.ErrInvalidMetadata};data,e:=os.ReadFile(p);if e!=nil{return r,e};defer clear(data);d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields();if e=d.Decode(&r);e!=nil{return r,e};var extra any;if !errors.Is(d.Decode(&extra),io.EOF){return r,storage.ErrInvalidMetadata};return r,nil
}
